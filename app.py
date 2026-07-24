import os
from datetime import datetime

import click
from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash

from models import (
    REPORT_THRESHOLD_PRODUCT,
    REPORT_THRESHOLD_USER,
    ChatRead,
    Message,
    Product,
    Report,
    Transfer,
    User,
    db,
    dm_room_name,
    utcnow,
)
from utils import (
    admin_required,
    clean_text,
    is_locked,
    login_required,
    rate_limited,
    register_failed_login,
    reset_failed_login,
    valid_amount,
    valid_password,
    valid_price,
    valid_username,
)

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "SECRET_KEY 환경변수가 설정되어 있지 않습니다. "
        "`python -c \"import secrets; print(secrets.token_hex(32))\"` 로 생성 후 .env 파일에 넣어주세요."
    )
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///market.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30분 후 세션 만료

DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

db.init_app(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app)


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    return response


@app.errorhandler(CSRFError)
def csrf_error(_e):
    flash("요청이 만료되었거나 위조가 의심됩니다. 다시 시도해주세요.")
    return render_template("403.html"), 400


@app.errorhandler(403)
def forbidden(_e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(_e):
    db.session.rollback()
    return render_template("500.html"), 500


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


@app.context_processor
def inject_current_user():
    return {"current_user": current_user()}


_EPOCH = datetime(1970, 1, 1)


def get_conversations(user):
    """user가 참여 중인 1:1 채팅방 목록을, 최근 메시지/안읽은 개수와 함께 반환."""
    rooms = (
        db.session.query(Message.room)
        .filter(or_(Message.room.like(f"dm:{user.id}:%"), Message.room.like(f"dm:%:{user.id}")))
        .distinct()
        .all()
    )
    conversations = []
    for (room,) in rooms:
        parts = room.split(":")
        if len(parts) != 3:
            continue
        other_id = parts[2] if parts[1] == user.id else parts[1]
        other = db.session.get(User, other_id)
        if not other:
            continue
        last_msg = Message.query.filter_by(room=room).order_by(Message.created_at.desc()).first()
        read = db.session.get(ChatRead, (user.id, room))
        since = read.last_read_at if read else _EPOCH
        unread = Message.query.filter(
            Message.room == room, Message.sender_id != user.id, Message.created_at > since
        ).count()
        conversations.append(
            {
                "other_id": other.id,
                "other_username": other.username,
                "last_message": last_msg.content if last_msg else "",
                "last_message_at": last_msg.created_at.isoformat() if last_msg else "",
                "unread": unread,
            }
        )
    conversations.sort(key=lambda c: c["last_message_at"], reverse=True)
    return conversations


def mark_room_read(user, room):
    read = db.session.get(ChatRead, (user.id, room))
    if read:
        read.last_read_at = utcnow()
    else:
        db.session.add(ChatRead(user_id=user.id, room=room, last_read_at=utcnow()))
    db.session.commit()


# ---------------------------------------------------------------- 기본/인증

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = clean_text(request.form.get("username", ""), 20)
        password = request.form.get("password", "")
        if not valid_username(username):
            flash("아이디는 영문/숫자/밑줄 3~20자로 입력해주세요.")
            return redirect(url_for("register"))
        if not valid_password(password):
            flash("비밀번호는 8자 이상 128자 이하로 입력해주세요.")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first() is not None:
            flash("이미 존재하는 사용자명입니다.")
            return redirect(url_for("register"))
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash("회원가입이 완료되었습니다. 로그인 해주세요.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = clean_text(request.form.get("username", ""), 20)
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        # 아이디 존재 여부가 드러나지 않도록 실패 사유는 항상 동일한 문구로 안내
        generic_error = "아이디 또는 비밀번호가 올바르지 않습니다."

        if user is None:
            flash(generic_error)
            return redirect(url_for("login"))
        if is_locked(user):
            flash("로그인 시도가 너무 많아 계정이 잠시 잠겼습니다. 잠시 후 다시 시도해주세요.")
            return redirect(url_for("login"))
        if not check_password_hash(user.password_hash, password):
            register_failed_login(user, db)
            flash(generic_error)
            return redirect(url_for("login"))
        if user.is_dormant:
            flash("신고 누적으로 휴면 처리된 계정입니다. 관리자에게 문의해주세요.")
            return redirect(url_for("login"))

        reset_failed_login(user, db)
        session.clear()
        session["user_id"] = user.id
        session.permanent = True
        flash("로그인 성공!")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("index"))


# ---------------------------------------------------------------- 대시보드/검색

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    products = Product.query.filter_by(status="active").order_by(Product.created_at.desc()).all()
    history = Message.query.filter_by(room="global").order_by(Message.created_at.desc()).limit(50).all()
    history.reverse()
    return render_template("dashboard.html", products=products, user=user, chat_history=history)


@app.route("/search")
@login_required
def search():
    query = clean_text(request.args.get("q", ""), 100)
    results = []
    if query:
        pattern = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        results = (
            Product.query.filter(Product.status == "active")
            .filter(Product.title.ilike(f"%{pattern}%", escape="\\"))
            .order_by(Product.created_at.desc())
            .all()
        )
    return render_template("search.html", query=query, results=results)


# ---------------------------------------------------------------- 프로필/사용자 조회

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        bio = clean_text(request.form.get("bio", ""), 500)
        new_password = request.form.get("new_password", "")
        if new_password:
            if not valid_password(new_password):
                flash("새 비밀번호는 8자 이상 128자 이하로 입력해주세요.")
                return redirect(url_for("profile"))
            user.password_hash = generate_password_hash(new_password)
        user.bio = bio
        db.session.commit()
        flash("프로필이 업데이트되었습니다.")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)


@app.route("/user/<user_id>")
@login_required
def view_user(user_id):
    target = User.query.get_or_404(user_id)
    products = Product.query.filter_by(seller_id=target.id, status="active").all()
    return render_template("user_public.html", target=target, products=products)


# ---------------------------------------------------------------- 상품

@app.route("/product/new", methods=["GET", "POST"])
@login_required
def new_product():
    if request.method == "POST":
        title = clean_text(request.form.get("title", ""), 100)
        description = clean_text(request.form.get("description", ""), 2000)
        price = request.form.get("price", "")
        if not title or not description:
            flash("제목과 설명을 입력해주세요.")
            return redirect(url_for("new_product"))
        if not valid_price(price):
            flash("가격은 1원 이상 1억원 이하의 숫자로 입력해주세요.")
            return redirect(url_for("new_product"))
        product = Product(title=title, description=description, price=int(price), seller_id=session["user_id"])
        db.session.add(product)
        db.session.commit()
        flash("상품이 등록되었습니다.")
        return redirect(url_for("dashboard"))
    return render_template("new_product.html")


@app.route("/product/<product_id>")
@login_required
def view_product(product_id):
    product = Product.query.get_or_404(product_id)
    user = current_user()
    is_owner_or_admin = user.id == product.seller_id or user.is_admin
    if product.status == "blocked" and not is_owner_or_admin:
        abort(404)
    return render_template("view_product.html", product=product, seller=product.seller, is_owner_or_admin=is_owner_or_admin)


@app.route("/product/<product_id>/edit", methods=["GET", "POST"])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    user = current_user()
    if product.seller_id != user.id and not user.is_admin:
        abort(403)
    if request.method == "POST":
        title = clean_text(request.form.get("title", ""), 100)
        description = clean_text(request.form.get("description", ""), 2000)
        price = request.form.get("price", "")
        if not title or not description or not valid_price(price):
            flash("입력값을 확인해주세요.")
            return redirect(url_for("edit_product", product_id=product_id))
        product.title = title
        product.description = description
        product.price = int(price)
        db.session.commit()
        flash("상품이 수정되었습니다.")
        return redirect(url_for("view_product", product_id=product.id))
    return render_template("edit_product.html", product=product)


@app.route("/product/<product_id>/delete", methods=["POST"])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    user = current_user()
    if product.seller_id != user.id and not user.is_admin:
        abort(403)
    db.session.delete(product)
    db.session.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for("my_products"))


@app.route("/my/products")
@login_required
def my_products():
    products = Product.query.filter_by(seller_id=session["user_id"]).order_by(Product.created_at.desc()).all()
    return render_template("my_products.html", products=products)


# ---------------------------------------------------------------- 송금

@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    user = current_user()
    if request.method == "POST":
        recipient_username = clean_text(request.form.get("recipient", ""), 20)
        recipient = User.query.filter_by(username=recipient_username).first()
        amount_raw = request.form.get("amount", "")

        if recipient is None:
            flash("받는 사람을 찾을 수 없습니다.")
            return redirect(url_for("transfer"))
        if recipient.id == user.id:
            flash("본인에게는 송금할 수 없습니다.")
            return redirect(url_for("transfer"))
        if recipient.is_dormant:
            flash("휴면 계정으로는 송금할 수 없습니다.")
            return redirect(url_for("transfer"))
        if not valid_amount(amount_raw, user.balance):
            flash("송금 금액이 올바르지 않거나 잔액이 부족합니다.")
            return redirect(url_for("transfer"))

        amount = int(amount_raw)
        user.balance -= amount
        recipient.balance += amount
        db.session.add(Transfer(sender_id=user.id, receiver_id=recipient.id, amount=amount))
        db.session.commit()
        flash(f"{recipient.username}님에게 {amount:,}원을 송금했습니다.")
        return redirect(url_for("transfer"))

    history = (
        Transfer.query.filter((Transfer.sender_id == user.id) | (Transfer.receiver_id == user.id))
        .order_by(Transfer.created_at.desc())
        .limit(20)
        .all()
    )
    return render_template("transfer.html", user=user, history=history)


# ---------------------------------------------------------------- 신고

@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    # target_id의 의미는 대상 유형에 따라 다름:
    #  - product: 상품 UUID (제목은 중복될 수 있어 고유 식별 불가)
    #  - user: 사용자명 (username은 가입 시 유니크가 보장되므로 UUID 대신 사용, 화면에 UUID 노출 방지)
    if request.method == "POST":
        target_type = request.form.get("target_type", "")
        target_id = clean_text(request.form.get("target_id", ""), 36)
        reason = clean_text(request.form.get("reason", ""), 500)

        if target_type not in ("user", "product") or not target_id or not reason:
            flash("입력값을 확인해주세요.")
            return redirect(url_for("report"))

        if target_type == "product":
            target_exists = db.session.get(Product, target_id) is not None
        else:
            reporter = db.session.get(User, session["user_id"])
            if target_id == reporter.username:
                flash("본인을 신고할 수 없습니다.")
                return redirect(url_for("report"))
            target_exists = User.query.filter_by(username=target_id).first() is not None

        if not target_exists:
            flash("신고 대상을 찾을 수 없습니다.")
            return redirect(url_for("report"))

        exists = Report.query.filter_by(
            reporter_id=session["user_id"], target_type=target_type, target_id=target_id
        ).first()
        if exists:
            flash("이미 신고한 대상입니다.")
            return redirect(url_for("report"))

        db.session.add(
            Report(reporter_id=session["user_id"], target_type=target_type, target_id=target_id, reason=reason)
        )
        db.session.commit()

        count = Report.query.filter_by(target_type=target_type, target_id=target_id).count()
        if target_type == "product" and count >= REPORT_THRESHOLD_PRODUCT:
            product = db.session.get(Product, target_id)
            if product and product.status != "blocked":
                product.status = "blocked"
                db.session.commit()
        elif target_type == "user" and count >= REPORT_THRESHOLD_USER:
            target_user = User.query.filter_by(username=target_id).first()
            if target_user and not target_user.is_dormant:
                target_user.is_dormant = True
                db.session.commit()

        flash("신고가 접수되었습니다.")
        return redirect(url_for("dashboard"))

    target_type = request.args.get("type", "")
    target_id = clean_text(request.args.get("id", ""), 36)
    target_label = None

    if target_type == "product" and target_id:
        target = db.session.get(Product, target_id)
        target_label = target.title if target else None
    elif target_type == "user" and target_id:
        target = User.query.filter_by(username=target_id).first()
        target_label = target.username if target else None

    if not target_label:
        # UUID를 직접 입력받지 않음: 상품/사용자 상세 페이지의 "신고하기" 링크를 통해서만 접근 가능
        return render_template("report.html", target_type=None, target_id=None, target_label=None)

    return render_template("report.html", target_type=target_type, target_id=target_id, target_label=target_label)


# ---------------------------------------------------------------- 1:1 채팅 페이지

@app.route("/chat/<user_id>")
@login_required
def chat_with(user_id):
    other = User.query.get_or_404(user_id)
    me = current_user()
    if other.id == me.id:
        abort(400)
    room = dm_room_name(me.id, other.id)
    history = Message.query.filter_by(room=room).order_by(Message.created_at.desc()).limit(50).all()
    history.reverse()
    mark_room_read(me, room)
    return render_template("chat_room.html", other=other, history=history, room=room)


# ---------------------------------------------------------------- 메신저 API (대화 목록 / 안읽은 메시지)

@app.route("/api/conversations")
@login_required
def api_conversations():
    return jsonify(get_conversations(current_user()))


@app.route("/api/unread_count")
@login_required
def api_unread_count():
    total = sum(c["unread"] for c in get_conversations(current_user()))
    return jsonify({"unread": total})


@app.route("/api/chat/<other_id>/messages")
@login_required
def api_chat_messages(other_id):
    me = current_user()
    other = db.session.get(User, other_id)
    if not other or other.id == me.id:
        abort(404)
    room = dm_room_name(me.id, other.id)
    history = Message.query.filter_by(room=room).order_by(Message.created_at.desc()).limit(50).all()
    history.reverse()
    mark_room_read(me, room)
    return jsonify(
        {
            "other_id": other.id,
            "other_username": other.username,
            "messages": [
                {
                    "username": m.sender.username if m.sender else "알수없음",
                    "message": m.content,
                    "mine": m.sender_id == me.id,
                }
                for m in history
            ],
        }
    )


# ---------------------------------------------------------------- 관리자

@app.route("/admin")
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    products = Product.query.order_by(Product.created_at.desc()).all()
    reports = Report.query.order_by(Report.created_at.desc()).limit(200).all()
    return render_template("admin.html", users=users, products=products, reports=reports)


@app.route("/admin/user/<user_id>/toggle-dormant", methods=["POST"])
@admin_required
def admin_toggle_dormant(user_id):
    user = User.query.get_or_404(user_id)
    user.is_dormant = not user.is_dormant
    db.session.commit()
    flash(f"{user.username} 휴면 상태가 변경되었습니다.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/product/<product_id>/toggle-block", methods=["POST"])
@admin_required
def admin_toggle_block(product_id):
    product = Product.query.get_or_404(product_id)
    product.status = "blocked" if product.status == "active" else "active"
    db.session.commit()
    flash(f"{product.title} 상태가 변경되었습니다.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/product/<product_id>/delete", methods=["POST"])
@admin_required
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for("admin_dashboard"))


@app.cli.command("create-admin")
@click.argument("username")
def create_admin(username):
    """지정한 사용자명을 관리자로 승격합니다. 최초 관리자 계정을 만들 때만 사용하세요."""
    user = User.query.filter_by(username=username).first()
    if not user:
        click.echo(f'사용자 "{username}"를 찾을 수 없습니다. 먼저 회원가입을 해주세요.')
        return
    user.is_admin = True
    db.session.commit()
    click.echo(f'"{username}" 계정이 관리자로 지정되었습니다.')


# ---------------------------------------------------------------- 실시간 채팅 (Socket.IO)

@socketio.on("connect")
def handle_connect():
    if "user_id" not in session:
        return False  # 인증되지 않은 연결은 거부
    user = db.session.get(User, session["user_id"])
    if not user or user.is_dormant:
        return False
    join_room("global")
    join_room(f"user:{user.id}")  # 이 유저 전용 알림 채널 (안읽은 메시지 뱃지 push용)


@socketio.on("send_message")
def handle_send_message_event(data):
    user = current_user()
    if not user or user.is_dormant:
        return
    if rate_limited(f"chat:{user.id}", limit=5, window_seconds=10):
        return
    content = clean_text((data or {}).get("message", ""), 500)
    if not content:
        return
    msg = Message(room="global", sender_id=user.id, content=content)
    db.session.add(msg)
    db.session.commit()
    # 클라이언트가 보낸 username은 신뢰하지 않고 서버 세션 기준으로 발신자를 고정
    emit("message", {"username": user.username, "message": content}, room="global")


@socketio.on("join_dm")
def handle_join_dm(data):
    user = current_user()
    if not user:
        return False
    other_id = (data or {}).get("other_id", "")
    other = db.session.get(User, other_id) if other_id else None
    if not other:
        return False
    join_room(dm_room_name(user.id, other.id))


@socketio.on("leave_dm")
def handle_leave_dm(data):
    user = current_user()
    if not user:
        return
    other_id = (data or {}).get("other_id", "")
    other = db.session.get(User, other_id) if other_id else None
    if not other:
        return
    leave_room(dm_room_name(user.id, other.id))


@socketio.on("send_dm")
def handle_send_dm(data):
    user = current_user()
    if not user or user.is_dormant:
        return
    other_id = (data or {}).get("other_id", "")
    other = db.session.get(User, other_id) if other_id else None
    if not other:
        return
    if rate_limited(f"dm:{user.id}", limit=5, window_seconds=10):
        return
    content = clean_text((data or {}).get("message", ""), 500)
    if not content:
        return
    room = dm_room_name(user.id, other.id)
    msg = Message(room=room, sender_id=user.id, content=content)
    db.session.add(msg)
    db.session.commit()
    emit("dm_message", {"username": user.username, "message": content, "other_id": user.id}, room=room)
    # 상대방이 지금 이 방을 보고 있지 않아도 뱃지가 갱신되도록 개인 알림 채널로 push
    unread_total = sum(c["unread"] for c in get_conversations(other))
    socketio.emit("dm_notify", {"unread": unread_total, "from": user.username}, room=f"user:{other.id}")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # Werkzeug 내장 서버는 실제 운영 배포용이 아님. 이 과제 범위(로컬/ngrok 테스트)에서는
    # allow_unsafe_werkzeug로 명시적으로 허용하되, 실제 운영 배포 시에는 gunicorn+eventlet
    # 등 별도의 WSGI 서버를 사용해야 함 (SECURITY_NOTES.md 참고).
    socketio.run(app, debug=DEBUG, allow_unsafe_werkzeug=True)
