# app.py
# Secure Payment Gateway Simulator – PCI DSS Style
# UPDATED: Stronger password policy + password history (prevent reuse) + Merchant Payees & Transaction View

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, current_app, jsonify, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from functools import wraps
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy import or_, and_

import secrets
import random
import string
import os
import base64
import json
from datetime import datetime, timedelta
from io import StringIO
import csv
import uuid
import re

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ------------------ Flask App ------------------
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', secrets.token_hex(16))

# ------------------ Mail Config ------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nfsucryptoproject@gmail.com'
app.config['MAIL_PASSWORD'] = 'hafv ehby surl chnp'  # App password
app.config['MAIL_DEFAULT_SENDER'] = 'nfsucryptoproject@gmail.com'

mail = Mail(app)
bcrypt = Bcrypt(app)

# ------------------ Database (Neon PostgreSQL) ------------------
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql://neondb_owner:npg_hXEzBYRvt91k'
    '@ep-red-snow-ad0nq1l5-pooler.c-2.us-east-1.aws.neon.tech/neondb'
    '?sslmode=require&channel_binding=require'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Handle stale Neon connections better
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 300
}

db = SQLAlchemy(app)

# ------------------ Crypto Key (Demo Only) ------------------
try:
    _ENCRYPTION_KEY_RAW = os.environ.get('AES_KEY', None)
    if _ENCRYPTION_KEY_RAW:
        ENCRYPTION_KEY = _ENCRYPTION_KEY_RAW.encode('utf-8').ljust(32, b'\0')[:32]
    else:
        ENCRYPTION_KEY = secrets.token_bytes(32)
except Exception:
    ENCRYPTION_KEY = b"a" * 32  # fallback

PASSWORD_RESET_TTL_MINUTES = 15
# Brute-force config
MAX_FAILED_ATTEMPTS = 3
ACCOUNT_LOCK_DURATION = timedelta(days=1)

# ------------------ Password policy configuration ------------------
MIN_PASSWORD_LENGTH = 12
PASSWORD_HISTORY_COUNT = 4

# Small deny-list of common passwords (add more as needed)
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "12345678",
    "111111", "1234567", "iloveyou", "123123", "abc123",
    "password1", "admin", "letmein", "welcome", "monkey"
}

# ------------------ Models ------------------

class AdminUser(db.Model):
    __tablename__ = 'admin_users'
    sno = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(6), nullable=False)
    ip_address = db.Column(db.String(50))
    # NEW: brute-force protection fields
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)


class MerchantUser(db.Model):
    __tablename__ = 'merchant_users'
    sno = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(6), nullable=False)
    ip_address = db.Column(db.String(50))
    # NEW: brute-force protection fields
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)


class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    activity_type = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default='INFO', index=True)
    user_email = db.Column(db.String(255))
    role = db.Column(db.String(50))
    ip_address = db.Column(db.String(100))
    details = db.Column(db.Text)


class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.String(64), primary_key=True)  # uuid hex
    merchant_email = db.Column(db.String(120), index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    currency = db.Column(db.String(10), default='USD')
    status = db.Column(db.String(30), nullable=False)
    token = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    customer_name = db.Column(db.String(200))
    purchase_description = db.Column(db.String(400))

    # --- Payee / Settlement fields (new) ---
    payee_id = db.Column(db.Integer, index=True, nullable=True)
    payee_account_name = db.Column(db.String(200))
    payee_account_masked = db.Column(db.String(64))
    payee_acquirer = db.Column(db.String(120))
    settlement_status = db.Column(db.String(50), default='pending')
    settlement_date = db.Column(db.DateTime, nullable=True)


class PasswordReset(db.Model):
    __tablename__ = 'password_resets'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'merchant'
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class UserDevice(db.Model):
    __tablename__ = 'user_devices'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), index=True, nullable=False)
    device_id = db.Column(db.String(64), index=True, nullable=False)
    user_agent = db.Column(db.String(255))
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_country = db.Column(db.String(100))
    last_city = db.Column(db.String(100))


class LoginHistory(db.Model):
    __tablename__ = 'login_history'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), index=True, nullable=False)
    device_id = db.Column(db.String(64))
    ip_address = db.Column(db.String(100))
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    login_time = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success = db.Column(db.Boolean, default=False)
    risk_level = db.Column(db.String(20))
    notes = db.Column(db.Text)


class PasswordHistory(db.Model):
    """
    Store historical password hashes for preventing reuse.
    We store bcrypt hashes and timestamp; to check reuse we bcrypt-check
    the candidate password against these hashes.
    """
    __tablename__ = 'password_history'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), index=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'merchant'
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class MerchantPayee(db.Model):
    """
    Simple model representing a payee/account where merchant sends payments.
    For demo we store a masked identifier only (PCI-friendly).
    """
    __tablename__ = 'merchant_payees'
    id = db.Column(db.Integer, primary_key=True)
    merchant_email = db.Column(db.String(120), index=True, nullable=False)  # owner
    account_name = db.Column(db.String(200), nullable=False)
    account_identifier = db.Column(db.String(64))  # raw identifier (dev only) - avoid storing raw PAN in prod
    account_identifier_masked = db.Column(db.String(64))  # precomputed masked display
    acquirer = db.Column(db.String(120))
    currency = db.Column(db.String(10), default='USD')
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------ Utility & Security Functions ------------------

def login_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'email' not in session or session.get('role') != role:
                flash("Access denied. Please log in with the correct role.", 'error')
                return redirect(url_for('index'))
            if not session.get('verified'):
                flash("Authentication required. Please verify OTP.", 'error')
                return redirect(url_for('verify_otp'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


def redact_sensitive(text):
    if text is None:
        return text
    redacted = str(text)

    def mask_pan(match):
        pan = match.group(0)
        if len(pan) <= 10:
            return pan
        return pan[:6] + '*' * (len(pan) - 10) + pan[-4:]

    redacted = re.sub(r'\b\d{13,19}\b', mask_pan, redacted)
    redacted = re.sub(r'(?i)(cvv\D{0,3})\d{3,4}', r'\1***', redacted)
    return redacted


def log_activity(activity_type, details, severity='INFO'):
    try:
        user = session.get('email', 'N/A')
    except Exception:
        user = 'N/A'
    try:
        role = session.get('role', 'N/A')
    except Exception:
        role = 'N/A'
    try:
        ip = request.remote_addr if (globals().get('request') is not None and hasattr(request, 'remote_addr')) else 'N/A'
    except Exception:
        ip = 'N/A'

    try:
        safe_details = redact_sensitive(details)
    except Exception:
        safe_details = "[REDACTION_FAILED]"

    try:
        entry = SecurityLog(
            timestamp=datetime.utcnow(),
            activity_type=activity_type,
            severity=(severity or 'INFO').upper(),
            user_email=user,
            role=role,
            ip_address=ip,
            details=safe_details
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        print(f"[AUDIT LOG FALLBACK {datetime.utcnow()}] {severity} {activity_type} | ROLE: {role} | USER: {user} | IP: {ip} | DETAILS: {safe_details} | ERROR: {e}")


def send_otp_email(email, otp):
    try:
        msg = Message('Secure Gateway OTP', recipients=[email])
        msg.body = f'Your One-Time Password (OTP) for Secure Gateway access is: {otp}'
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Flask-Mail Error (OTP): {e}")
        return False


def send_reset_email(email, token, role):
    reset_link = url_for('reset_password', token=token, _external=True)
    subject = "Password Reset for Secure Gateway"
    body = (
        f"You requested a password reset for role={role}.\n\n"
        f"Click the link below to reset your password (valid for {PASSWORD_RESET_TTL_MINUTES} minutes):\n\n{reset_link}\n\n"
        "If you didn't request this, ignore this message."
    )
    try:
        msg = Message(subject, recipients=[email])
        msg.body = body
        mail.send(msg)
        log_activity("PASSWORD_RESET_SENT", f"Password reset email sent to {email} for role {role}", severity='INFO')
        return True
    except Exception as e:
        log_activity("PASSWORD_RESET_SEND_FAILED", f"Failed to send reset email to {email}. Token: {token}. Error: {e}", severity='WARNING')
        return False

# ----------- IP Geolocation Stub -----------
def get_ip_geolocation(ip_address: str):
    if not ip_address:
        return "Unknown", "Unknown"

    private_prefixes = (
        "127.", "10.", "192.168.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.2", "172.3"
    )
    if ip_address.startswith(private_prefixes):
        return "India", "Local Development"

    return "Unknown", "Unknown"

# ----------- Login Risk Evaluation -----------
def evaluate_login_risk(email: str):
    ip = request.remote_addr or "0.0.0.0"
    country, city = get_ip_geolocation(ip)

    device_cookie_id = request.cookies.get('device_id')
    is_known_device = False
    if device_cookie_id:
        existing = UserDevice.query.filter_by(
            user_email=email,
            device_id=device_cookie_id
        ).first()
        if existing:
            is_known_device = True

    last_login = LoginHistory.query.filter_by(
        user_email=email,
        success=True
    ).order_by(LoginHistory.login_time.desc()).first()

    last_country = last_login.country if last_login else None

    if country == "Unknown" or last_country is None:
        is_familiar_location = True
    else:
        is_familiar_location = (country == last_country)

    if is_known_device and is_familiar_location:
        risk = 'LOW'
    elif (not is_known_device) and is_familiar_location:
        risk = 'MEDIUM'
    elif is_known_device and (not is_familiar_location):
        risk = 'MEDIUM'
    else:
        risk = 'HIGH'

    log_activity(
        "LOGIN_RISK_EVAL",
        f"email={email} | ip={ip} | country={country} | last_country={last_country} | "
        f"is_known_device={is_known_device} | risk={risk}",
        severity='INFO' if risk in ('LOW', 'MEDIUM') else 'CRITICAL'
    )

    session['login_risk_level'] = risk
    session['login_is_known_device'] = is_known_device
    session['login_country'] = country
    session['login_city'] = city
    session['login_ip'] = ip

    return risk


def finalize_successful_login(email: str, role: str, redirect_url: str):
    ip = session.pop('login_ip', request.remote_addr or "0.0.0.0")
    country = session.pop('login_country', 'Unknown')
    city = session.pop('login_city', 'Unknown')
    risk = session.pop('login_risk_level', 'LOW')
    is_known_device = session.pop('login_is_known_device', False)

    ua = request.headers.get('User-Agent', 'unknown')[:255]
    cookie_device_id = request.cookies.get('device_id') if is_known_device else None
    device_id = None

    try:
        if is_known_device and cookie_device_id:
            device_id = cookie_device_id
            device = UserDevice.query.filter_by(
                user_email=email,
                device_id=device_id
            ).first()
            if device:
                device.last_seen_at = datetime.utcnow()
                device.last_country = country
                device.last_city = city
                device.user_agent = ua
            else:
                device_id = secrets.token_hex(16)
                device = UserDevice(
                    user_email=email,
                    device_id=device_id,
                    user_agent=ua,
                    first_seen_at=datetime.utcnow(),
                    last_seen_at=datetime.utcnow(),
                    last_country=country,
                    last_city=city
                )
                db.session.add(device)
        else:
            device_id = secrets.token_hex(16)
            device = UserDevice(
                user_email=email,
                device_id=device_id,
                user_agent=ua,
                first_seen_at=datetime.utcnow(),
                last_seen_at=datetime.utcnow(),
                last_country=country,
                last_city=city
            )
            db.session.add(device)

        history = LoginHistory(
            user_email=email,
            device_id=device_id,
            ip_address=ip,
            country=country,
            city=city,
            login_time=datetime.utcnow(),
            success=True,
            risk_level=risk,
            notes=f"role={role}"
        )
        db.session.add(history)
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        log_activity(
            "LOGIN_HISTORY_DEVICE_UPDATE_FAILED",
            f"email={email} role={role} ip={ip} country={country} city={city} error={e}",
            severity='ERROR'
        )

    resp = make_response(redirect(redirect_url))
    if device_id:
        resp.set_cookie(
            'device_id',
            device_id,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            secure=False  # set True in HTTPS
        )
    return resp

# ------------------ Password policy & history helpers ------------------

def _meets_character_requirements(pw: str) -> bool:
    """Check character class requirements."""
    if len(pw) < MIN_PASSWORD_LENGTH:
        return False
    if not re.search(r'[A-Z]', pw):
        return False
    if not re.search(r'[a-z]', pw):
        return False
    if not re.search(r'[0-9]', pw):
        return False
    if not re.search(r'[^A-Za-z0-9]', pw):
        return False
    return True

def _is_common_password(pw: str) -> bool:
    return pw.lower() in COMMON_PASSWORDS

def _recent_password_hashes(email: str, role: str, limit: int = PASSWORD_HISTORY_COUNT):
    """Return most recent password history hashes for a user+role."""
    return (PasswordHistory.query
            .filter_by(user_email=email, role=role)
            .order_by(PasswordHistory.created_at.desc())
            .limit(limit)
            .all())

def validate_password_policy(candidate: str, email: str = None, role: str = None):
    """
    Validates candidate password:
      - length and character classes
      - not a common password
      - not in last PASSWORD_HISTORY_COUNT (if email+role provided)
    Returns (True, None) on success, or (False, message) on failure.
    """
    if not candidate:
        return False, "Password required."

    if len(candidate) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."

    if not re.search(r'[A-Z]', candidate):
        return False, "Password must include at least one uppercase letter."

    if not re.search(r'[a-z]', candidate):
        return False, "Password must include at least one lowercase letter."

    if not re.search(r'[0-9]', candidate):
        return False, "Password must include at least one digit."

    if not re.search(r'[^A-Za-z0-9]', candidate):
        return False, "Password must include at least one special character."

    if _is_common_password(candidate):
        return False, "Password is too common. Choose a stronger password."

    # Check history reuse
    if email and role:
        try:
            recent = _recent_password_hashes(email, role)
            for ph in recent:
                try:
                    if bcrypt.check_password_hash(ph.password_hash, candidate):
                        return False, f"Password reuse detected. You cannot reuse the last {PASSWORD_HISTORY_COUNT} passwords."
                except Exception:
                    # if bcrypt compare fails for any reason, continue checking others
                    continue
        except Exception:
            # Non-fatal: if DB read fails, be conservative and deny reuse checks? We'll just continue.
            pass

    return True, None

def record_password_history(email: str, role: str, hashed_password: str):
    """Insert password hash into history and prune to last PASSWORD_HISTORY_COUNT entries."""
    try:
        ph = PasswordHistory(user_email=email, role=role, password_hash=hashed_password)
        db.session.add(ph)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return

    # prune older entries
    try:
        histories = (PasswordHistory.query
                     .filter_by(user_email=email, role=role)
                     .order_by(PasswordHistory.created_at.desc())
                     .all())
        # keep newest PASSWORD_HISTORY_COUNT
        for old in histories[PASSWORD_HISTORY_COUNT:]:
            try:
                db.session.delete(old)
            except Exception:
                pass
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass

# ------------------ Encryption / Tokenization ------------------

def encrypt_card_data(card_details):
    sensitive_data_json = json.dumps(card_details, sort_keys=True).encode('utf-8')
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(sensitive_data_json) + encryptor.finalize()
    tag = encryptor.tag

    secure_token = {
        'ct': base64.b64encode(ciphertext).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
    }

    log_activity("DATA_ENCRYPTED", f"Token generated for {card_details.get('customer_name', 'N/A')}", severity='INFO')
    return json.dumps(secure_token)


def mock_decrypt_data_at_rest(encrypted_token_json):
    try:
        secure_token = json.loads(encrypted_token_json)
        ct = base64.b64decode(secure_token['ct'])
        iv = base64.b64decode(secure_token['iv'])
        tag = base64.b64decode(secure_token['tag'])

        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(ct) + decryptor.finalize()
        decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))

        log_activity("MOCK_DECRYPT_SUCCESS", f"Decrypted Customer: {decrypted_data.get('customer_name', 'N/A')}", severity='INFO')
        return decrypted_data
    except Exception as e:
        log_activity("MOCK_DECRYPT_FAILED", f"Decryption failed due to: {e}", severity='ERROR')
        return {"error": "Decryption Failed - Invalid Key or Data"}

# ------------------ Routes ------------------

@app.route("/")
def index():
    return render_template('index.html')

# ---------- ADMIN LOGIN / SIGNUP WITH BRUTE-FORCE PROTECTION ----------

@app.route("/admin/login", methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = AdminUser.query.filter_by(email=email).first()

        if not user:
            log_activity("ADMIN_LOGIN_FAILED_UNKNOWN", f"Login attempt for unknown admin {email}", severity='WARNING')
            error = 'Invalid email or password.'
            return render_template('admin_login.html', error=error)

        # 1) Check if account is already locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            log_activity(
                "ADMIN_LOGIN_BLOCKED_LOCKED_ACCOUNT",
                f"Locked admin account {email} attempted login. Locked_until={user.locked_until.isoformat()}",
                severity='CRITICAL'
            )
            error = "Your account is locked due to multiple failed login attempts. Please try again after 24 hours."
            return render_template('admin_login.html', error=error)

        # 2) Check password
        if bcrypt.check_password_hash(user.password, password):
            # Successful password → reset brute-force counters
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()

            # Evaluate risk BEFORE OTP
            risk = evaluate_login_risk(email)

            if risk == 'HIGH':
                log_activity(
                    "ADMIN_LOGIN_BLOCKED_SUSPICIOUS",
                    f"High-risk login blocked for {email}",
                    severity='CRITICAL'
                )
                try:
                    history = LoginHistory(
                        user_email=email,
                        device_id=request.cookies.get('device_id'),
                        ip_address=session.get('login_ip'),
                        country=session.get('login_country'),
                        city=session.get('login_city'),
                        login_time=datetime.utcnow(),
                        success=False,
                        risk_level=risk,
                        notes="High-risk admin login blocked before OTP"
                    )
                    db.session.add(history)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    log_activity("LOGIN_HISTORY_WRITE_FAILED", f"admin high-risk block history error={e}", severity='ERROR')

                error = "Suspicious login attempt detected from unusual device/location. Access has been blocked."
                return render_template('admin_login.html', error=error)

            # Risk LOW/MED → proceed with OTP
            session['email'] = email
            session['role'] = 'admin'
            session['verified'] = False

            new_otp = generate_otp()
            user.otp_secret = new_otp
            db.session.commit()
            if send_otp_email(email, new_otp):
                log_activity("ADMIN_LOGIN_INITIATED", f"OTP sent to {email} with risk={risk}", severity='INFO')
                return redirect(url_for('verify_otp'))
            else:
                log_activity("ADMIN_EMAIL_FAILED", f"OTP send failed for {email}", severity='WARNING')
                error = 'Could not send OTP email. Check server logs.'
        else:
            # Wrong password → increment failed_attempts
            user.failed_attempts = (user.failed_attempts or 0) + 1
            remaining = MAX_FAILED_ATTEMPTS - user.failed_attempts
            lock_triggered = False

            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.utcnow() + ACCOUNT_LOCK_DURATION
                lock_triggered = True

            db.session.commit()

            if lock_triggered:
                log_activity(
                    "ADMIN_ACCOUNT_LOCKED_BRUTE_FORCE",
                    f"Admin account {email} locked for {ACCOUNT_LOCK_DURATION} after {user.failed_attempts} failed attempts.",
                    severity='CRITICAL'
                )
                error = "Too many failed login attempts. Your admin account has been locked for 24 hours."
            else:
                log_activity(
                    "ADMIN_LOGIN_FAILED",
                    f"Invalid admin credentials for {email}. Failed_attempts={user.failed_attempts}",
                    severity='WARNING'
                )
                error = f"Invalid email or password. Remaining attempts before lock: {max(0, remaining)}."

    return render_template('admin_login.html', error=error)

@app.route("/admin/signup", methods=['GET', 'POST'])
def admin_signup():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        ip_address = request.remote_addr

        if password != confirm_password:
            error = 'Password and confirmation do not match.'
            return render_template('admin_signup.html', error=error)

        ok, msg = validate_password_policy(password, email=email, role='admin')
        if not ok:
            error = msg
            return render_template('admin_signup.html', error=error)

        if not error:
            try:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                entry = AdminUser(
                    email=email,
                    password=hashed_password,
                    otp_secret=generate_otp(),
                    ip_address=ip_address,
                    failed_attempts=0,
                    locked_until=None
                )
                db.session.add(entry)
                db.session.commit()

                # record password history
                record_password_history(email, 'admin', hashed_password)

                log_activity("ADMIN_ACCOUNT_CREATED", f"Admin user {email} registered from {ip_address}", severity='INFO')
                flash("Admin account created! Please log in.", 'success')
                return redirect(url_for('admin_login'))
            except IntegrityError:
                db.session.rollback()
                error = 'Email address is already registered.'
    return render_template('admin_signup.html', error=error)

# ---------- MERCHANT LOGIN / SIGNUP WITH BRUTE-FORCE PROTECTION ----------

@app.route("/merchant/login", methods=['GET', 'POST'])
def merchant_login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = MerchantUser.query.filter_by(email=email).first()

        if not user:
            log_activity("MERCHANT_LOGIN_FAILED_UNKNOWN", f"Login attempt for unknown merchant {email}", severity='WARNING')
            error = 'Invalid email or password.'
            return render_template('merchant_login.html', error=error)

        # 1) Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            log_activity(
                "MERCHANT_LOGIN_BLOCKED_LOCKED_ACCOUNT",
                f"Locked merchant account {email} attempted login. Locked_until={user.locked_until.isoformat()}",
                severity='CRITICAL'
            )
            error = "Your account is locked due to multiple failed login attempts. Please try again after 24 hours."
            return render_template('merchant_login.html', error=error)

        # 2) Check password
        if bcrypt.check_password_hash(user.password, password):
            # Successful password → reset brute-force counters
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()

            # Evaluate risk BEFORE OTP
            risk = evaluate_login_risk(email)

            if risk == 'HIGH':
                log_activity(
                    "MERCHANT_LOGIN_BLOCKED_SUSPICIOUS",
                    f"High-risk login blocked for {email}",
                    severity='CRITICAL'
                )
                try:
                    history = LoginHistory(
                        user_email=email,
                        device_id=request.cookies.get('device_id'),
                        ip_address=session.get('login_ip'),
                        country=session.get('login_country'),
                        city=session.get('login_city'),
                        login_time=datetime.utcnow(),
                        success=False,
                        risk_level=risk,
                        notes="High-risk merchant login blocked before OTP"
                    )
                    db.session.add(history)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    log_activity("LOGIN_HISTORY_WRITE_FAILED", f"merchant high-risk block history error={e}", severity='ERROR')

                error = "Suspicious login attempt detected from unusual device/location. Access has been blocked."
                return render_template('merchant_login.html', error=error)

            # Risk LOW/MED → proceed with OTP
            session['email'] = email
            session['role'] = 'merchant'
            session['verified'] = False

            new_otp = generate_otp()
            user.otp_secret = new_otp
            db.session.commit()
            if send_otp_email(email, new_otp):
                log_activity("MERCHANT_LOGIN_INITIATED", f"OTP sent to {email} with risk={risk}", severity='INFO')
                return redirect(url_for('verify_otp'))
            else:
                log_activity("MERCHANT_EMAIL_FAILED", f"OTP send failed for {email}", severity='WARNING')
                error = 'Could not send OTP email. Check server logs.'
        else:
            # Wrong password → increment failed_attempts
            user.failed_attempts = (user.failed_attempts or 0) + 1
            remaining = MAX_FAILED_ATTEMPTS - user.failed_attempts
            lock_triggered = False

            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.utcnow() + ACCOUNT_LOCK_DURATION
                lock_triggered = True

            db.session.commit()

            if lock_triggered:
                log_activity(
                    "MERCHANT_ACCOUNT_LOCKED_BRUTE_FORCE",
                    f"Merchant account {email} locked for {ACCOUNT_LOCK_DURATION} after {user.failed_attempts} failed attempts.",
                    severity='CRITICAL'
                )
                error = "Too many failed login attempts. Your merchant account has been locked for 24 hours."
            else:
                log_activity(
                    "MERCHANT_LOGIN_FAILED",
                    f"Invalid merchant credentials for {email}. Failed_attempts={user.failed_attempts}",
                    severity='WARNING'
                )
                error = f"Invalid email or password. Remaining attempts before lock: {max(0, remaining)}."

    return render_template('merchant_login.html', error=error)

@app.route("/merchant/signup", methods=['GET', 'POST'])
def merchant_signup():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        ip_address = request.remote_addr

        if password != confirm_password:
            error = 'Password and confirmation do not match.'
            return render_template('merchant_signup.html', error=error)

        ok, msg = validate_password_policy(password, email=email, role='merchant')
        if not ok:
            error = msg
            return render_template('merchant_signup.html', error=error)

        if not error:
            try:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                entry = MerchantUser(
                    email=email,
                    password=hashed_password,
                    otp_secret=generate_otp(),
                    ip_address=ip_address,
                    failed_attempts=0,
                    locked_until=None
                )
                db.session.add(entry)
                db.session.commit()

                # record password history
                record_password_history(email, 'merchant', hashed_password)

                log_activity("MERCHANT_ACCOUNT_CREATED", f"Merchant user {email} registered from {ip_address}", severity='INFO')
                flash("Merchant account created! Please log in.", 'success')
                return redirect(url_for('merchant_login'))
            except IntegrityError:
                db.session.rollback()
                error = 'Email address is already registered.'
    return render_template('merchant_signup.html', error=error)

# ---------- OTP Verification ----------

@app.route("/verify_otp", methods=['GET', 'POST'])
def verify_otp():
    if 'email' not in session or 'role' not in session:
        flash("Please log in again.", 'error')
        return redirect(url_for('index'))

    email = session['email']
    role = session['role']

    UserClass = AdminUser if role == 'admin' else MerchantUser
    user = UserClass.query.filter_by(email=email).first()

    if not user:
        session.clear()
        flash("User not found or role error.", 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        otp_entered = request.form.get('otp')

        if otp_entered == user.otp_secret:
            session['verified'] = True
            log_activity("LOGIN_SUCCESS", f"User {email} verified OTP for role: {role}.", severity='INFO')

            target = url_for('admin_dashboard') if role == 'admin' else url_for('merchant_dashboard')
            return finalize_successful_login(email, role, target)
        else:
            log_activity("OTP_FAILED", f"User {email} entered incorrect OTP for role: {role}.", severity='WARNING')
            return render_template('verify_otp.html', email=email, error="Incorrect OTP. Please check your email and try again.")
    return render_template('verify_otp.html', email=email)

# ---------- Dashboards & Logout ----------

@app.route("/admin/dashboard")
@login_required('admin')
def admin_dashboard():
    email = session['email']
    recent_logins = LoginHistory.query.filter_by(
        user_email=email
    ).order_by(LoginHistory.login_time.desc()).limit(5).all()

    last_risk = recent_logins[0].risk_level if recent_logins else None

    return render_template(
        'admin_dashboard.html',
        email=email,
        recent_logins=recent_logins,
        last_risk=last_risk
    )

@app.route("/merchant/dashboard")
@login_required('merchant')
def merchant_dashboard():
    email = session['email']
    recent_logins = LoginHistory.query.filter_by(
        user_email=email
    ).order_by(LoginHistory.login_time.desc()).limit(3).all()

    last_risk = recent_logins[0].risk_level if recent_logins else None

    return render_template(
        'merchant_dashboard.html',
        email=email,
        recent_logins=recent_logins,
        last_risk=last_risk
    )

@app.route("/admin/logout", methods=['POST'])
def admin_logout():
    if session.get('role') == 'admin':
        log_activity("ADMIN_LOGOUT", f"Admin user {session['email']} logged out.", severity='INFO')
        session.clear()
    return redirect(url_for('index'))

@app.route("/merchant/logout", methods=['POST'])
def merchant_logout():
    if session.get('role') == 'merchant':
        log_activity("MERCHANT_LOGOUT", f"Merchant user {session['email']} logged out.", severity='INFO')
        session.clear()
    return redirect(url_for('index'))

# ---------- Merchant Payees (Create/List) ----------
@app.route("/merchant/payees", methods=['GET', 'POST'])
@login_required('merchant')
def merchant_payees():
    email = session.get('email')
    message = None
    error = None

    if request.method == 'POST':
        # form fields from merchant_payees.html
        account_name = request.form.get('account_name')
        account_identifier = request.form.get('account_identifier') or ''
        acquirer = request.form.get('acquirer') or ''
        currency = request.form.get('currency') or 'USD'
        is_default = bool(request.form.get('is_default'))

        if not account_name:
            error = "Account name is required."
        else:
            masked = account_identifier
            if len(masked) >= 4:
                masked = f"****{masked[-4:]}"
            else:
                masked = f"****{masked}"
            payee = MerchantPayee(
                merchant_email=email,
                account_name=account_name,
                account_identifier=account_identifier,
                account_identifier_masked=masked,
                acquirer=acquirer,
                currency=currency,
                is_default=is_default
            )
            try:
                if is_default:
                    # unset other defaults
                    MerchantPayee.query.filter_by(merchant_email=email, is_default=True).update({"is_default": False})
                db.session.add(payee)
                db.session.commit()
                message = "Payee created."
            except Exception as e:
                db.session.rollback()
                error = f"Could not create payee: {e}"

    payees = MerchantPayee.query.filter_by(merchant_email=email).order_by(MerchantPayee.created_at.desc()).all()
    return render_template('merchant_payees.html', payees=payees, message=message, error=error)

# ---------- Payment & Transactions ----------

@app.route("/payment_form", methods=['GET'])
@login_required('merchant')
def payment_form():
    email = session.get('email')
    # pass merchant payees to template for selection
    merchant_accounts = MerchantPayee.query.filter_by(merchant_email=email).order_by(MerchantPayee.is_default.desc(), MerchantPayee.created_at.desc()).all()
    return render_template('payment_form.html', merchant_accounts=merchant_accounts)

@app.route("/process_payment", methods=['POST'])
@login_required('merchant')
def process_payment():
    card_details = {
        'card_number': request.form.get('card_number'),
        'expiry_date': request.form.get('expiry_date'),
        'cvv': request.form.get('cvv'),
        'amount': request.form.get('amount'),
        'customer_name': request.form.get('customer_name'),
        'purchase_description': request.form.get('purchase_description')
    }

    merchant_email = session.get('email')
    amount_raw = request.form.get('amount') or '0'
    try:
        amount_val = round(float(amount_raw), 2)
    except Exception:
        amount_val = 0.00

    encrypted_token_json = encrypt_card_data(card_details)
    decrypted_data = mock_decrypt_data_at_rest(encrypted_token_json)

    txn_id = uuid.uuid4().hex

    # read payee_id from form
    payee_id = request.form.get('payee_id') or None
    payee_obj = None
    if payee_id:
        try:
            payee_obj = MerchantPayee.query.filter_by(id=int(payee_id), merchant_email=merchant_email).first()
        except Exception:
            payee_obj = None

    txn = Transaction(
        id=txn_id,
        merchant_email=merchant_email,
        amount=amount_val,
        currency=request.form.get('currency') or 'USD',
        status='success' if encrypted_token_json else 'failed',
        token=(encrypted_token_json if encrypted_token_json else None),
        customer_name=card_details.get('customer_name'),
        purchase_description=card_details.get('purchase_description'),
        payee_id=(payee_obj.id if payee_obj else None),
        payee_account_name=(payee_obj.account_name if payee_obj else None),
        payee_account_masked=(payee_obj.account_identifier_masked if payee_obj else None),
        payee_acquirer=(payee_obj.acquirer if payee_obj else None)
    )
    try:
        db.session.add(txn)
        db.session.commit()
        log_activity("TX_SUCCESS", f"Transaction {txn_id} for {merchant_email} amount {amount_val}", severity='INFO')
    except Exception as e:
        db.session.rollback()
        log_activity("TX_CREATE_FAILED", f"Failed to create transaction {txn_id}: {e}", severity='ERROR')

    message = f"Transaction processed (id={txn_id}). Mock decrypted name: {decrypted_data.get('customer_name', 'N/A')}."
    # return to the form and keep accounts available
    merchant_accounts = MerchantPayee.query.filter_by(merchant_email=merchant_email).order_by(MerchantPayee.is_default.desc(), MerchantPayee.created_at.desc()).all()
    return render_template('payment_form.html', message=message, merchant_accounts=merchant_accounts)

@app.route("/merchant/transactions")
@login_required('merchant')
def merchant_transactions():
    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
    try:
        per_page = min(200, max(5, int(request.args.get('per_page', 20))))
    except ValueError:
        per_page = 20

    status_filter = request.args.get('status', None)
    q = request.args.get('q', None)

    query = Transaction.query.filter(Transaction.merchant_email == session.get('email'))

    if status_filter and status_filter.lower() != 'all':
        query = query.filter(Transaction.status.ilike(status_filter))

    if q:
        like_q = f"%{q}%"
        query = query.filter(or_(
            Transaction.customer_name.ilike(like_q),
            Transaction.purchase_description.ilike(like_q),
            Transaction.id.ilike(like_q)
        ))

    query = query.order_by(Transaction.timestamp.desc())

    try:
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        txns = pagination.items
    except OperationalError as e:
        db.session.rollback()
        log_activity(
            "TX_HISTORY_DB_ERROR",
            f"Failed to load transaction history for {session.get('email')} due to DB error: {e}",
            severity='ERROR'
        )
        flash("Database connection issue while loading transactions. Please try again in a moment.", "error")
        pagination = None
        txns = []

    return render_template(
        'merchant_transactions.html',
        txns=txns,
        pagination=pagination,
        per_page=per_page,
        q=q,
        status_filter=status_filter
    )

# View single transaction details
@app.route("/merchant/transaction/<tx_id>")
@login_required('merchant')
def merchant_transaction_view(tx_id):
    txn = Transaction.query.filter_by(id=tx_id, merchant_email=session.get('email')).first_or_404()
    return render_template('merchant_transaction_view.html', txn=txn)

# ---------- Password Reset ----------

@app.route("/password_reset_request", methods=['GET', 'POST'])
def password_reset_request():
    error = None
    message = None

    if request.method == 'POST':
        email = request.form.get('email')
        role = request.form.get('role')

        if role not in ('admin', 'merchant'):
            error = "Invalid role selected."
        else:
            UserClass = AdminUser if role == 'admin' else MerchantUser
            user = UserClass.query.filter_by(email=email).first()
            message = "If an account exists for that email, a reset link will be sent."

            if not user:
                log_activity("PASSWORD_RESET_REQUEST_UNKNOWN", f"Reset requested for unknown {email} role {role}", severity='WARNING')
            else:
                token = secrets.token_urlsafe(32)
                expires = datetime.utcnow() + timedelta(minutes=PASSWORD_RESET_TTL_MINUTES)
                pr = PasswordReset(token=token, email=email, role=role, expires_at=expires, used=False)
                try:
                    db.session.add(pr)
                    db.session.commit()
                    send_reset_email(email, token, role)
                    log_activity("PASSWORD_RESET_REQUESTED", f"Password reset requested for {email} role {role}", severity='INFO')
                except Exception as e:
                    db.session.rollback()
                    log_activity("PASSWORD_RESET_CREATE_FAILED", f"Failed to create reset record for {email}: {e}", severity='ERROR')
                    error = "Could not create reset request. Try again later."

    return render_template('reset_request.html', error=error, message=message)

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token') or request.form.get('token')
    if not token:
        flash("Missing token.", 'error')
        return redirect(url_for('password_reset_request'))

    pr = PasswordReset.query.filter_by(token=token, used=False).first()
    if not pr:
        flash("Invalid or used token.", 'error')
        return redirect(url_for('password_reset_request'))

    if pr.expires_at < datetime.utcnow():
        pr.used = True
        db.session.commit()
        flash("Token expired. Request a new password reset.", 'error')
        return redirect(url_for('password_reset_request'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if not new_password or new_password != confirm:
            return render_template('reset_password.html', token=token, error="Password must match confirmation.")

        ok, msg = validate_password_policy(new_password, email=pr.email, role=pr.role)
        if not ok:
            return render_template('reset_password.html', token=token, error=msg)

        UserClass = AdminUser if pr.role == 'admin' else MerchantUser
        user = UserClass.query.filter_by(email=pr.email).first()

        if not user:
            pr.used = True
            db.session.commit()
            flash("User not found.", 'error')
            return redirect(url_for('password_reset_request'))

        try:
            hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed
            # Also reset brute-force counters on password reset
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()

            # record password history (prune older)
            record_password_history(pr.email, pr.role, hashed)

            pr.used = True
            db.session.commit()
            log_activity("PASSWORD_RESET_COMPLETE", f"Password reset for {pr.email} role {pr.role}", severity='INFO')
            flash("Password reset successful. Please log in.", 'success')
            return redirect(url_for('admin_login') if pr.role == 'admin' else url_for('merchant_login'))
        except Exception as e:
            db.session.rollback()
            log_activity("PASSWORD_RESET_FAILED", f"Password reset failed for {pr.email}: {e}", severity='ERROR')
            return render_template('reset_password.html', token=token, error="An error occurred. Try again later.")

    return render_template('reset_password.html', token=token)

# ---------- Admin Logs (Filters + Export) ----------

@app.route("/admin/logs")
@login_required('admin')
def admin_logs():
    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
    try:
        per_page = min(200, max(5, int(request.args.get('per_page', 20))))
    except ValueError:
        per_page = 20

    q = request.args.get('q', None)
    severity_filter = request.args.get('severity', None)
    start_date_str = request.args.get('start', None)
    end_date_str = request.args.get('end', None)
    export = request.args.get('export', None)

    query = SecurityLog.query
    filters = []

    if q:
        like_q = f"%{q}%"
        filters.append(or_(
            SecurityLog.activity_type.ilike(like_q),
            SecurityLog.user_email.ilike(like_q),
            SecurityLog.details.ilike(like_q)
        ))

    if severity_filter and severity_filter.upper() != 'ALL':
        filters.append(SecurityLog.severity == severity_filter.upper())

    try:
        if start_date_str:
            start_dt = datetime.strptime(start_date_str, "%Y-%m-%d")
            filters.append(SecurityLog.timestamp >= start_dt)
        if end_date_str:
            end_dt = datetime.strptime(end_date_str, "%Y-%m-%d") + timedelta(days=1)
            filters.append(SecurityLog.timestamp < end_dt)
    except Exception:
        pass

    if filters:
        query = query.filter(and_(*filters))

    query = query.order_by(SecurityLog.timestamp.desc())

    if export and export.lower() in ('csv', 'json'):
        logs = query.all()
        if export.lower() == 'json':
            out = [{
                "id": l.id,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                "activity_type": l.activity_type,
                "severity": l.severity,
                "user_email": l.user_email,
                "role": l.role,
                "ip_address": l.ip_address,
                "details": l.details
            } for l in logs]
            return current_app.response_class(json.dumps(out, default=str), mimetype='application/json')
        else:
            si = StringIO()
            writer = csv.writer(si)
            writer.writerow(['id', 'timestamp', 'activity_type', 'severity', 'user_email', 'role', 'ip_address', 'details'])
            for l in logs:
                details_clean = (l.details or "").replace("\n", " ").replace("\r", " ")
                writer.writerow([
                    l.id,
                    l.timestamp.isoformat() if l.timestamp else "",
                    l.activity_type,
                    l.severity,
                    l.user_email or "",
                    l.role or "",
                    l.ip_address or "",
                    details_clean
                ])
            output = si.getvalue()
            return current_app.response_class(
                output,
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment;filename=security_logs.csv'}
            )

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items
    severity_options = ['ALL', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

    return render_template(
        'admin_logs.html',
        logs=logs,
        pagination=pagination,
        q=q,
        per_page=per_page,
        severity=severity_filter,
        severity_options=severity_options,
        start=start_date_str,
        end=end_date_str
    )

# ---------- Admin Manual Unlock (just logs action) ----------

@app.route("/admin/unlock_user", methods=['POST'])
@login_required('admin')
def admin_unlock_user():
    email = request.form.get('email')
    role = request.form.get('role', 'merchant')

    UserClass = AdminUser if role == 'admin' else MerchantUser
    user = UserClass.query.filter_by(email=email).first()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('admin_dashboard'))

    # In a real system, admin could clear lock here; for demo we only log:
    log_activity("ADMIN_MANUAL_UNLOCK", f"Admin {session.get('email')} ran manual unlock for {role} account {email}", severity='INFO')
    flash(f"Action recorded for {email}", "success")
    return redirect(url_for('admin_dashboard'))

# ---------- Debug Endpoint ----------

@app.route('/debug/my_transactions')
@login_required('merchant')
def debug_my_transactions():
    my_email = session.get('email')
    txs = Transaction.query.filter_by(merchant_email=my_email).order_by(Transaction.timestamp.desc()).limit(50).all()
    out = []
    for t in txs:
        out.append({
            "id": t.id,
            "timestamp": t.timestamp.isoformat() if t.timestamp else None,
            "amount": str(t.amount),
            "status": t.status,
            "customer_name": t.customer_name,
            "description": t.purchase_description,
            "payee": t.payee_account_name,
            "payee_masked": t.payee_account_masked
        })
    return jsonify({"merchant": my_email, "count": len(out), "transactions": out})

# ------------------ Main ------------------

if __name__ == '__main__':
    with app.app_context():
        print("Using DB:", app.config['SQLALCHEMY_DATABASE_URI'])
        db.create_all()
        print("Database tables created/checked on Neon DB.")
    app.run(debug=True)
