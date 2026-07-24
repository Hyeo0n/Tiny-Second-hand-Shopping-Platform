import uuid
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

REPORT_THRESHOLD_PRODUCT = 3   # 이 횟수 이상 신고되면 상품 자동 차단
REPORT_THRESHOLD_USER = 5      # 이 횟수 이상 신고되면 유저 자동 휴면
STARTING_BALANCE = 1_000_000   # 가입 시 지급되는 초기 잔액 (실습용)


def gen_uuid():
    return str(uuid.uuid4())


def utcnow():
    # SQLite/SQLAlchemy는 tzinfo를 보존하지 않고 naive datetime으로 되돌려주므로,
    # 저장 시점부터 naive UTC로 통일해서 이후 비교 시 aware/naive 불일치를 방지함.
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.String(500), nullable=False, default="")
    balance = db.Column(db.Integer, nullable=False, default=STARTING_BALANCE)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_dormant = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    products = db.relationship("Product", backref="seller", lazy=True)


class Product(db.Model):
    __tablename__ = "product"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(2000), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    seller_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="active")  # active | blocked
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class Report(db.Model):
    __tablename__ = "report"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    reporter_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    target_type = db.Column(db.String(10), nullable=False)  # user | product
    target_id = db.Column(db.String(36), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        # 동일 신고자가 같은 대상을 반복 신고해서 임계치를 조작하는 것을 방지
        db.UniqueConstraint("reporter_id", "target_type", "target_id", name="uq_report_once"),
    )


class Message(db.Model):
    __tablename__ = "message"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    room = db.Column(db.String(80), nullable=False, index=True)  # 'global' or 'dm:<id1>:<id2>'
    sender_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])


class ChatRead(db.Model):
    __tablename__ = "chat_read"

    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), primary_key=True)
    room = db.Column(db.String(80), primary_key=True)
    last_read_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class Transfer(db.Model):
    __tablename__ = "transfer"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    sender_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])


def dm_room_name(user_id_a, user_id_b):
    a, b = sorted([user_id_a, user_id_b])
    return f"dm:{a}:{b}"
