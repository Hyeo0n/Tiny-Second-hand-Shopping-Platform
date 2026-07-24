import re
import time
from datetime import timedelta
from functools import wraps

from flask import abort, flash, redirect, session, url_for

from models import utcnow

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 128

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def valid_username(value):
    return bool(value) and bool(USERNAME_RE.match(value))


def valid_password(value):
    return bool(value) and PASSWORD_MIN_LEN <= len(value) <= PASSWORD_MAX_LEN


def valid_price(value):
    try:
        amount = int(value)
    except (TypeError, ValueError):
        return False
    return 0 < amount <= 100_000_000


def valid_amount(value, max_value):
    try:
        amount = int(value)
    except (TypeError, ValueError):
        return False
    return 0 < amount <= max_value


def clean_text(value, max_len):
    if value is None:
        return ""
    return value.strip()[:max_len]


def is_locked(user):
    return bool(user.locked_until and user.locked_until > utcnow())


def register_failed_login(user, db):
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
        user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        user.failed_login_attempts = 0
    db.session.commit()


def reset_failed_login(user, db):
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        from models import User

        user_id = session.get("user_id")
        if not user_id:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        # 세션은 남아있지만 DB에 해당 계정이 없는 경우(예: DB 초기화) 방어
        if User.query.get(user_id) is None:
            session.clear()
            flash("세션이 만료되었습니다. 다시 로그인해주세요.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        from models import User

        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        user = User.query.get(session["user_id"])
        if not user or not user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


# 아주 단순한 in-memory rate limiter. 프로세스 재시작 시 초기화되고
# 다중 워커 환경에서는 워커별로 따로 카운트되는 한계가 있음(실습 규모에선 허용).
_rate_buckets = {}


def rate_limited(key, limit, window_seconds):
    now = time.time()
    bucket = _rate_buckets.setdefault(key, [])
    while bucket and bucket[0] < now - window_seconds:
        bucket.pop(0)
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False
