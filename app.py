# ============================================================================
# 1. IMPORTS
# ============================================================================

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, Blueprint, jsonify, g, send_from_directory
from flask_restful import Resource, Api
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from flask_cors import CORS
import sqlite3
from password_strength import PasswordPolicy, PasswordStats
import os
import jwt
from google.oauth2 import service_account
from google.auth.transport.requests import Request
import vertexai
import time
from google import genai
from google.genai.types import GenerateContentConfig
import tempfile
import uuid
from urllib.parse import unquote_plus
from datetime import datetime, timedelta, timezone
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import certifi
from enum import Enum

# ============================================================================
# 2. APP INITIALIZATION & CONFIGURATION
# ============================================================================

load_dotenv()
app = Flask(__name__)
CORS(app)

app.secret_key = os.getenv('FLASK_SECRET')
if not app.secret_key:
    print("❌ ERROR: FLASK_SECRET not found in environment!")
    print("Current directory:", os.getcwd())
    print("Looking for .env file...")
    if os.path.exists('.env'):
        print("✅ .env file exists")
    else:
        print("❌ .env file NOT FOUND")
    raise ValueError("FLASK_SECRET must be set in .env file")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
api_bp = Blueprint("auth", __name__)
api = Api(app)
auth = HTTPBasicAuth()


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEBUG'] = True
app.config["WTF_CSRF_ENABLED"] = True
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['ADMIN_KEY'] = os.getenv('ADMIN_KEY')

app.config['UPLOAD_FOLDER'] = os.path.join(
    os.path.dirname(__file__), 'static', 'uploads')
app.config['EDITED_FOLDER'] = os.path.join(
    os.path.dirname(__file__), 'static', 'edited')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['EDITED_FOLDER'], exist_ok=True)

s = URLSafeTimedSerializer(app.secret_key)
mail = Mail(app)

# Google Cloud Setup
PROJECT_ID = os.getenv("PROJECT_ID")
LOCATION = os.getenv("LOCATION", "us-central1")
service_key_json = os.getenv("SERVICE_KEY_JSON")
local_credentials = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
credentials_path = None

if service_key_json:
    key_path = os.path.join(tempfile.gettempdir(), "vertex-key.json")
    with open(key_path, "w") as f:
        f.write(service_key_json)
    credentials_path = key_path
    print("✅ Using SERVICE_KEY_JSON from environment")
elif local_credentials and os.path.exists(local_credentials):
    credentials_path = local_credentials
    print(f"✅ Using local credentials: {local_credentials}")

if credentials_path:
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=SCOPES
    )
    credentials.refresh(Request())
    vertexai.init(project=PROJECT_ID, location=LOCATION)
    genai_client = genai.Client(
        vertexai=True, project=PROJECT_ID, location=LOCATION)
    print("✅ Google Cloud AI initialized")
else:
    genai_client = None
    print("⚠️ Google Cloud credentials not configured - image editing disabled")


policy = PasswordPolicy.from_names(
    length=8,
    uppercase=1,
    numbers=1,
    special=1,
    nonletters=2,
)

MAX_ATTEMPTS = 5
LOCKOUT_TIME = timedelta(minutes=10)
DB_PATH = 'users.db'
SITE_KEY = '6LeGMZ8rAAAAACUTMzSF4iHC3GhOeMT_C3WG61XD'
SECRET_KEY = '6LeGMZ8rAAAAAKWYNlcOO8kFGihCe3TxhmPJxpra'
VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

# ============================================================================
# 3. DATABASE MODELS
# ============================================================================


class UserRole(Enum):
    ADMIN = 'admin'
    USER = 'user'
    SUPERADMIN = 'superadmin'


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email_id = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    role = db.Column(
        db.String(20), default='user', nullable=False)
    profile_picture = db.Column(db.String(200))

    def is_admin(self):
        return self.role in [UserRole.ADMIN.value, UserRole.SUPERADMIN.value]

    def is_superadmin(self):
        return self.role == UserRole.SUPERADMIN.value

# ============================================================================
# 4. DATABASE FUNCTIONS
# ============================================================================


def get_db_connection():
    conn = sqlite3.connect(
        DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email_id TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_verified BOOLEAN NOT NULL DEFAULT 0,
                role TEXT NOT NULL DEFAULT 'user',
                profile_picture TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts(
                email_id TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL,
                last_attempt TIMESTAMP NOT NULL,
                locked_until TIMESTAMP
            )
        ''')

        # API Keys table
        c.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                name TEXT,
                is_active BOOLEAN DEFAULT 1,
                rate_limit INTEGER DEFAULT 100,
                request_count INTEGER DEFAULT 0,
                last_used TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()


init_db()

# ============================================================================
# 5. HELPER FUNCTIONS
# ============================================================================


def generate_verification_token(email: str) -> str:
    payload = {
        "email_id": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24)
    }
    token = jwt.encode(
        payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")
    return token  # Remove quote_plus - not needed for JWT


def generate_reset_token(email: str) -> str:
    payload = {
        "email_id": email,
        # 1 hour for password reset
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }
    token = jwt.encode(
        payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")
    return token


def confirm_reset_token(token: str):
    try:
        data = jwt.decode(
            token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        return data.get("email_id")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def decode_verification_token(token: str) -> dict:
    token = unquote_plus(token)
    return jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])


def detect_face_in_image(image_path):
    """
    Detect if image contains a human face.
    Returns True if face detected, False otherwise.
    """
    try:
        import cv2
        import numpy as np

        # Load cascade classifier
        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

        # Read image
        img = cv2.imread(image_path)
        if img is None:
            return False

        # Convert to grayscale
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # Detect faces
        faces = face_cascade.detectMultiScale(
            gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

        return len(faces) > 0

    except Exception as e:
        print(f"⚠️ Face detection error: {e}")
        return False  # Default to allowing if detection fails

# ============================================================================
# 6. DECORATORS
# ============================================================================


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not g.current_user:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            if g.current_user.role not in roles:
                flash('Access forbidden: insufficient rights', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return {'message': 'Token is missing!'}, 401
            try:
                token = auth_header.split(" ")[1]
                data = jwt.decode(
                    token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
                user = Users.query.get(data['user_id'])
                if not user:
                    return {'message': 'User not found!'}, 404
                if role and user.role != role:
                    return {'message': 'Access forbidden: insufficient rights'}, 403
            except jwt.ExpiredSignatureError:
                return {'message': 'Token has expired!'}, 401
            except jwt.InvalidTokenError:
                return {'message': 'Invalid token!'}, 401
            return f(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("You are not authorized to view this page.", "danger")
            return redirect(url_for("welcome", user_id=session["user_id"]))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# 7. PUBLIC ROUTES
# ============================================================================


@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('home.html', site_key=SITE_KEY)

# ============================================================================
# 8. AUTHENTICATION ROUTES
# ============================================================================


@csrf.exempt
@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email_id = request.form.get('email_id', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'user')
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not (first_name and last_name and email_id and password):
            flash('Please fill all required fields.', 'danger')
            return render_template('register.html', first_name=first_name, last_name=last_name, email_id=email_id, site_key=SITE_KEY)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', first_name=first_name, last_name=last_name, email_id=email_id, site_key=SITE_KEY)

        stats = PasswordStats(password)
        validation_errors = policy.test(password)
        if validation_errors:
            error_messages = []
            for error in validation_errors:
                if hasattr(error, 'message'):
                    error_messages.append(error.message())
                else:
                    error_messages.append(str(error))
            flash(
                f'Password does not meet requirements: {", ".join(error_messages)}', 'danger')
            return render_template('register.html', first_name=first_name, last_name=last_name, email_id=email_id, site_key=SITE_KEY)

        try:
            verify_response = requests.post(
                VERIFY_URL,
                data={'secret': SECRET_KEY, 'response': recaptcha_response},
                verify=certifi.where()
            ).json()
        except Exception as e:
            flash(f"Captcha verification failed: {e}", 'danger')
            return render_template('register.html', first_name=first_name, last_name=last_name, email_id=email_id, site_key=SITE_KEY)

        if not verify_response.get('success'):
            flash('Captcha failed. Try again.', 'danger')
            return render_template('register.html', first_name=first_name, last_name=last_name, email_id=email_id, site_key=SITE_KEY)

        hashed_password = generate_password_hash(password)

        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT id FROM users WHERE email_id = ?', (email_id,))
                if c.fetchone():
                    flash('User already exists. Please log in.', 'warning')
                    return redirect(url_for('login'))

                c.execute('INSERT INTO users (first_name, last_name, email_id, password, role, is_verified) VALUES (?, ?, ?, ?, ?, ?)',
                          (first_name, last_name, email_id, hashed_password, role, 1 if role == 'admin' else 0))
                conn.commit()
        except Exception as e:
            app.logger.exception(f"Error during registration: {e}")
            flash(f'Registration failed due to internal error: {e}', 'danger')
            return render_template('register.html', first_name=first_name, last_name=last_name, email_id=email_id, site_key=SITE_KEY)

        try:
            token = generate_verification_token(email_id)
            verify_url = url_for('verify_email', token=token, _external=True)
            html = render_template('verify_email.html', verify_url=verify_url)
            subject = "Please verify your email"

            msg = Message(
                subject=subject,
                recipients=[email_id],
                sender=app.config['MAIL_USERNAME'],
                html=html
            )

            mail.send(msg)

            flash('Registration successful. Verification email sent!', 'success')
        except Exception as e:
            app.logger.exception(f'Failed to send verification email: {e}')
            flash(
                f'Registered but failed to send verification email. Please try again later. {e}', 'warning')

        session["user_id"] = c.lastrowid
        session["role"] = role

        if role == 'admin':
            return redirect(url_for('admin_dashboard'))

        return redirect(url_for('login'))

    return render_template('register.html', site_key=SITE_KEY)


@csrf.exempt
@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        data = jwt.decode(
            token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        email_id = data.get("email_id")

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute(
                'UPDATE users SET is_verified = 1 WHERE email_id = ?', (email_id,))
            if c.rowcount == 0:
                flash("User not found.", "danger")
                return redirect(url_for("register"))
            conn.commit()

        flash("Email verified successfully! You can now log in.", "success")
        return redirect(url_for("login"))

    except jwt.ExpiredSignatureError:
        flash("Verification link expired. Please register again.", "danger")
        return redirect(url_for("register"))
    except jwt.InvalidTokenError as e:
        print(f"Token decode error: {e}")
        flash("Invalid verification link.", "danger")
        return redirect(url_for("register"))


@csrf.exempt
@app.route('/login/', methods=['GET', 'POST'])
def login():
    email_id = ''
    site_key = SITE_KEY

    if request.method == 'POST':
        email_id = request.form.get('email_id', '').strip().lower()
        password = request.form.get('password', '')
        recaptcha_response = request.form.get('g-recaptcha-response')
        remember = 'remember' in request.form

        if not (email_id and password):
            flash('Please provide email ID and password.', 'danger')
            return render_template('login.html', email_id=email_id, site_key=SITE_KEY)

        verify_response = requests.post(
            VERIFY_URL,
            data={'secret': SECRET_KEY, 'response': recaptcha_response}).json()
        if not verify_response.get('success'):
            flash('Captcha failed. Try again.', 'danger')
            return render_template('login.html', email_id=email_id, site_key=SITE_KEY)

        now = datetime.now(timezone.utc)

        with get_db_connection() as conn:
            c = conn.cursor()

            c.execute(
                'SELECT attempts, locked_until FROM login_attempts WHERE email_id = ?', (email_id,))
            row = c.fetchone()

            if row:
                attempts = row['attempts']
                locked_until = row['locked_until']
                if locked_until is not None:
                    try:
                        locked_until_dt = datetime.fromisoformat(locked_until)
                    except Exception:
                        locked_until_dt = None

                    if locked_until_dt and now < locked_until_dt:
                        delta = locked_until_dt - now
                        minutes = int(delta.total_seconds()/60) + 1
                        flash(
                            f'Temporary lockout. Please try again in {minutes} minutes.', 'danger')
                        return render_template('login.html', email_id=email_id, site_key=SITE_KEY)

            c.execute(
                'SELECT id, email_id, password, is_verified, role FROM users WHERE email_id = ?', (email_id,))
            user = c.fetchone()

            if not user:

                if row:
                    attempts = row['attempts'] + 1
                    if attempts >= MAX_ATTEMPTS:
                        locked_until_dt = now + LOCKOUT_TIME
                        c.execute('UPDATE login_attempts SET attempts = ?, last_attempt = ?, locked_until = ? WHERE email_id = ?',
                                  (attempts, now.strftime('%Y-%m-%d %H:%M:%S'), locked_until_dt.isoformat(), email_id))
                    else:
                        c.execute('UPDATE login_attempts SET attempts = ?, last_attempt = ? WHERE email_id = ?',
                                  (attempts, now.strftime('%Y-%m-%d %H:%M:%S'), email_id))
                else:
                    attempts = 1
                    c.execute('INSERT INTO login_attempts (email_id, attempts, last_attempt, locked_until) VALUES (?, ?, ?, NULL)',
                              (email_id, attempts, now.strftime('%Y-%m-%d %H:%M:%S')))
                conn.commit()

                if attempts >= MAX_ATTEMPTS:
                    flash(
                        f'Too many failed attempts. Account locked for {LOCKOUT_TIME.seconds//60} minutes.', 'danger')
                    return render_template('login.html', email_id=email_id, site_key=SITE_KEY)
                else:
                    flash('User ID not registered. Please register first.', 'danger')
                    return redirect(url_for('register'))

            user_id = user['id']
            db_password = user['password']
            is_verified = user['is_verified']
            role = user['role']

            if not check_password_hash(db_password, password):

                if row:
                    attempts = row['attempts'] + 1
                    if attempts >= MAX_ATTEMPTS:
                        locked_until_dt = now + LOCKOUT_TIME
                        c.execute('UPDATE login_attempts SET attempts = ?, last_attempt = ?, locked_until = ? WHERE email_id = ?',
                                  (attempts, now.strftime('%Y-%m-%d %H:%M:%S'), locked_until_dt.isoformat(), email_id))
                        conn.commit()
                        flash(
                            f'Too many failed attempts. Account locked for {LOCKOUT_TIME.seconds//60} minutes.', 'danger')
                        return render_template('login.html', email_id=email_id, site_key=SITE_KEY)
                    else:
                        c.execute('UPDATE login_attempts SET attempts = ?, last_attempt = ? WHERE email_id = ?',
                                  (attempts, now.strftime('%Y-%m-%d %H:%M:%S'), email_id))
                else:
                    attempts = 1
                    c.execute('INSERT INTO login_attempts (email_id, attempts, last_attempt, locked_until) VALUES (?, ?, ?, NULL)',
                              (email_id, attempts, now.strftime('%Y-%m-%d %H:%M:%S')))
                conn.commit()

                remaining = max(0, MAX_ATTEMPTS - attempts)
                flash(
                    f'Incorrect password. {remaining} attempts left.', 'danger')
                return render_template('login.html', email_id=email_id, site_key=SITE_KEY)

            c.execute(
                'DELETE FROM login_attempts WHERE email_id = ?', (email_id,))
            conn.commit()

        if not is_verified:
            flash(
                'Email not verified. Please check your inbox for the verification email.', 'warning')
            return render_template('login.html', email_id=email_id, site_key=SITE_KEY)

        session["user_id"] = user_id
        session["role"] = role

        if session["role"] in ["admin", "superadmin"]:
            return redirect(url_for("admin_dashboard"))
        else:
            return redirect(url_for("welcome", user_id=session["user_id"]))

    return render_template('login.html', site_key=SITE_KEY, email_id=email_id)


@csrf.exempt
@app.route('/api-keys')
@login_required
def api_keys_page():
    """API key management page"""
    from app import get_db_connection

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT id, key_prefix, name, is_active, rate_limit, 
                   request_count, created_at, last_used, expires_at
            FROM api_keys
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (session['user_id'],))

    api_keys = c.fetchall()
    formatted_keys = []

    for row in api_keys:
        key = dict(row)   # convert sqlite row to dictionary

        # format dates safely
        key["created_at_str"] = (
            key["created_at"].strftime("%Y-%m-%d")
            if key["created_at"] else ""
        )

        key["expires_at_str"] = (
            key["expires_at"].strftime("%Y-%m-%d")
            if key["expires_at"] else "Never"
        )

        formatted_keys.append(key)

    return render_template('api_keys.html', api_keys=formatted_keys)


@app.route('/api-keys/create', methods=['POST'])
@login_required
def create_api_key_web():
    """Create API key via web interface"""
    from api.middleware.auth import generate_api_key
    import hashlib
    from datetime import datetime, timedelta, timezone

    name = request.form.get('name', 'My API Key')

    api_key = generate_api_key()
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    key_prefix = api_key[:15]
    expires_at = datetime.now(timezone.utc) + timedelta(days=365)

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO api_keys (user_id, key_hash, key_prefix, name, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (session['user_id'], key_hash, key_prefix, name, expires_at))
        conn.commit()

    flash(f'API Key Created: {api_key}', 'success')
    flash('Save this key now - it will not be shown again!', 'warning')

    return redirect(url_for('api_keys_page'))


@app.route('/api-keys/delete/<int:key_id>', methods=['POST'])
@login_required
def delete_api_key(key_id):
    """Delete API key"""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('DELETE FROM api_keys WHERE id = ? AND user_id = ?',
                  (key_id, session['user_id']))
        conn.commit()

    flash('API key deleted', 'success')
    return redirect(url_for('api_keys_page'))


@csrf.exempt
@app.route('/forgot_password/', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email_id = request.form.get('email_id', '').strip().lower()
        if not email_id:
            flash('Please enter your email address', 'danger')
            return render_template('forgot_password.html')

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute(
                'SELECT id, first_name FROM users WHERE email_id = ?', (email_id,))
            user = c.fetchone()

            if not user:
                flash('Email not found. Please register first.', 'danger')
                return render_template('forgot_password.html')

            token = generate_reset_token(email_id)
            reset_url = url_for('reset_password', token=token, _external=True)

            html = render_template(
                'reset_password_email.html', reset_url=reset_url, first_name=user['first_name'])
            subject = "Password Reset Requested"

            try:
                msg = Message(subject=subject,
                              recipients=[email_id],
                              sender=app.config['MAIL_USERNAME'],
                              html=html)
                mail.send(msg)
                flash('Password reset link sent. Check your email.', 'success')
            except Exception as e:
                app.logger.exception(f"Failed to send reset email: {e}")
                flash(
                    f'Failed to send reset email. Please try again later: {e}', 'danger')

        return render_template('forgot_password.html')

    return render_template('forgot_password.html')


@csrf.exempt
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = confirm_reset_token(token)
    if not email:
        flash('The reset link is invalid.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not password:
            flash('Please provide a password.', 'danger')
            return render_template('reset_password.html', token=token)

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('reset_password.html', token=token)

        errors = policy.test(password)
        if errors:
            flash('Password does not meet the requirements.', 'danger')
            return render_template('reset_password_form.html', token=token)

        hashed = generate_password_hash(password)

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET password=? WHERE email_id=?',
                      (hashed, email))
            conn.commit()

        flash('Your password has been updated. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password_form.html', token=token)


@app.route('/logout/')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('home'))

# ============================================================================
# 9. USER ROUTES (Lines 481-540)
# ============================================================================


@csrf.exempt
@app.route('/welcome/<int:user_id>')
def welcome(user_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    if session['user_id'] != user_id:
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            'SELECT first_name, last_name, profile_picture FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()

    if user:
        profile_pic = user['profile_picture'] if 'profile_picture' in user.keys(
        ) else None
        return render_template('welcome.html',
                               first_name=user['first_name'],
                               last_name=user['last_name'],
                               profile_picture=profile_pic)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

# ============================================================================
# 10. IMAGE PROCESSING ROUTES (Lines 541-640)
# ============================================================================


@app.route('/editor')
@login_required
def editor():
    """Image editor page - accessible only to logged-in users"""
    if 'user_id' not in session:
        flash('Please log in to access the editor.', 'warning')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT first_name, last_name FROM users WHERE id = ?',
                  (session['user_id'],))
        user = c.fetchone()

    return render_template('editor.html',
                           first_name=user['first_name'],
                           last_name=user['last_name'])


@csrf.exempt
@app.route('/api/edit-image', methods=['POST'])
@login_required
def edit_image_api():
    """
    API endpoint to edit uploaded image with company T-shirt
    Expects: multipart/form-data with 'image' file
    Returns: JSON with edited image URL
    """
    try:
        if not genai_client:
            return jsonify({"error": "Image editing service not configured"}), 503

        if 'image' not in request.files:
            return jsonify({"error": "No image uploaded"}), 400

        uploaded_file = request.files['image']
        if uploaded_file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Save uploaded image
        upload_filename = f"upload_{session['user_id']}_{uuid.uuid4().hex}.png"
        upload_path = os.path.join(
            app.config['UPLOAD_FOLDER'], upload_filename)
        uploaded_file.save(upload_path)

        # Read image bytes
        with open(upload_path, "rb") as f:
            image_bytes = f.read()

        # Check for human face
        if not detect_face_in_image(upload_path):
            os.remove(upload_path)  # Clean up
            return jsonify({"error": "No human face detected. Please upload a photo with a person."}), 400

        # Construct prompt for T-shirt replacement
        prompt = """Replace ONLY the shirt/t-shirt/top that the person is wearing with the company uniform t-shirt shown in the reference.

CRITICAL REQUIREMENTS:
1. Preserve EVERYTHING about the person: face, skin tone, hair, facial features, body shape, pose
2. Keep the EXACT same background, lighting, and image quality
3. ONLY change the shirt/t-shirt to match the company uniform design
4. The new t-shirt must fit naturally on the person's body with correct perspective and wrinkles
5. Maintain the same pose and arm positions
6. Keep all accessories (watches, glasses, etc.) unchanged

The company t-shirt design: Black t-shirt with white circular logo that says "SUPPORT SMALL BUSINESS" in a badge/stamp style, and the logo covers the entire front of the t-shirt not just a small area.

Apply this t-shirt design naturally to the person while preserving everything else in the image."""

        print(f"🖌️ Editing image for user {session['user_id']}...")

        # Call Gemini 2.5 Flash Image API
        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                response = genai_client.models.generate_content(
                    model="gemini-2.5-flash-image",
                    contents=[
                        {"role": "user", "parts": [
                            {"text": prompt},
                            {"inline_data": {
                                "mime_type": "image/png", "data": image_bytes}}
                        ]}
                    ],
                    config=GenerateContentConfig(
                        response_modalities=["IMAGE"],
                        candidate_count=1,
                    ),
                )
                break  # Success, exit retry loop

            except Exception as api_error:
                if "429" in str(api_error) or "RESOURCE_EXHAUSTED" in str(api_error):
                    if attempt < max_retries - 1:
                        print(
                            f"⚠️ Rate limit hit, retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    else:
                        return jsonify({"error": "API quota exceeded. Please try again in a few minutes."}), 429
                else:
                    raise

        # Save edited image
        edited_filename = f"edited_{session['user_id']}_{uuid.uuid4().hex}.png"
        edited_path = os.path.join(
            app.config['EDITED_FOLDER'], edited_filename)

        for part in response.candidates[0].content.parts:
            if hasattr(part, "inline_data"):
                with open(edited_path, "wb") as f:
                    f.write(part.inline_data.data)

        print(f"✅ Image edited successfully: {edited_filename}")

        # Return URL to edited image
        edited_url = f"/static/edited/{edited_filename}?v={int(time.time())}"
        original_url = f"/static/uploads/{upload_filename}?v={int(time.time())}"

        # Save profile picture path to database
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET profile_picture = ? WHERE id = ?',
                      (f"/static/edited/{edited_filename}", session['user_id']))
            conn.commit()

        return jsonify({
            "success": True,
            "original_url": original_url,
            "edited_url": edited_url,
            "message": "T-shirt applied successfully!"
        })

    except Exception as e:
        print(f"❌ Image editing error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to edit image: {str(e)}"}), 500


@app.route('/static/uploads/<filename>')
def serve_upload(filename):
    """Serve uploaded images - only to the user who uploaded them"""
    # Security: check if filename belongs to current user
    if not filename.startswith(f"upload_{session.get('user_id')}_"):
        abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/static/edited/<filename>')
def serve_edited(filename):
    """Serve edited images - only to the user who created them"""
    # Security: check if filename belongs to current user
    if not filename.startswith(f"edited_{session.get('user_id')}_"):
        abort(403)
    return send_from_directory(app.config['EDITED_FOLDER'], filename)

# ============================================================================
# 11. ADMIN ROUTES (Lines 641-740)
# ============================================================================


@csrf.exempt
@app.route('/admin/dashboard')
def admin_dashboard():
    if "user_id" not in session or session.get("role") not in ["admin", "superadmin"]:
        flash("Please log in to access this page.")
        return redirect(url_for("login"))

    conn = get_db_connection()
    users = conn.execute(
        'SELECT id, first_name, last_name, email_id, role, profile_picture FROM users').fetchall()
    conn.close()

    return render_template("admin_dashboard.html", users=users)


@csrf.exempt
@app.route('/admin/promote/<int:user_id>', methods=['POST'])
def promote_user(user_id):
    if session.get("role") != "superadmin":  # ADD THIS CHECK
        flash("Only superadmin can promote users.", "danger")
        return redirect(url_for('admin_dashboard'))

    with get_db_connection() as conn:
        conn.execute(
            "UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
        conn.commit()
    flash("User promoted to admin.", "success")
    return redirect(url_for('admin_dashboard'))


@csrf.exempt
@app.route('/admin/demote/<int:user_id>', methods=['POST'])
def demote_user(user_id):
    with get_db_connection() as conn:
        conn.execute("UPDATE users SET role = 'user' WHERE id = ?", (user_id,))
        conn.commit()
    flash("User demoted to user.", "warning")
    return redirect(url_for('admin_dashboard'))


@csrf.exempt
@app.route('/admin/delete-picture/<int:user_id>', methods=['POST'])
def delete_user_picture(user_id):
    if session.get("role") not in ["admin", "superadmin"]:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT profile_picture FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()

        if user and user['profile_picture']:
            # Delete file from filesystem
            file_path = os.path.join(os.path.dirname(
                __file__), user['profile_picture'].lstrip('/'))
            if os.path.exists(file_path):
                os.remove(file_path)

            # Update database
            c.execute(
                'UPDATE users SET profile_picture = NULL WHERE id = ?', (user_id,))
            conn.commit()
            flash("Profile picture deleted successfully.", "success")
        else:
            flash("No profile picture to delete.", "warning")

    return redirect(url_for('admin_dashboard'))


@app.route('/switch-to-admin')
@login_required
def switch_to_admin():
    """Allow admins to switch to admin view"""
    if session.get('role') not in ['admin', 'superadmin']:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('welcome', user_id=session['user_id']))

    return redirect(url_for('admin_dashboard'))


@app.route('/switch-to-user')
@login_required
def switch_to_user():
    """Allow admins to switch back to user view"""
    if session.get('role') not in ['admin', 'superadmin']:
        flash('Access denied.', 'danger')
        return redirect(url_for('welcome', user_id=session['user_id']))

    return redirect(url_for('welcome', user_id=session['user_id']))

# ============================================================================
# 12. API ENDPOINTS
# ============================================================================


class RegisterAPI(Resource):
    def post(self):
        data = request.get_json()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        email_id = data.get('email_id', '').strip().lower()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')

        if not (first_name and last_name and email_id and password):
            return {'message': 'Please fill all required fields.'}, 400

        if password != confirm_password:
            return {'message': 'Passwords do not match.'}, 400

        if Users.query.filter_by(email_id=email_id).first():
            return {"message": "User already exists"}, 409

        hashed_password = generate_password_hash(password)

        admin_key = data.get('admin_key')
        if admin_key == app.config['ADMIN_KEY']:
            role = UserRole.ADMIN.value
        else:
            role = UserRole.USER.value

        new_user = Users(first_name=first_name, last_name=last_name,
                         email_id=email_id, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        token = generate_verification_token(new_user.email_id)
        verification_link = url_for(
            'verifyemailapi', token=token, _external=True)

        subject = "Please verify your email address"

        body = f"Hi {first_name},\n\nPlease verify your email by clicking this link:\n{verification_link}\n\nThank you!"
QÅ9789O'/

C[P
        html = f"""<p>Hi {first_name},</p><p>Please verify your email by clicking the link below:</p><a href="{verification_link}" style="display:inline-block;padding:10px 20px;background:#007bff;color:#fff;text-decoration:none;border-radius:5px;">Verify Email</a><p9wsp[rjuaq8ð bu7yu>Thank you!</p>
        

        msg = Message(
            subject=subject,
            recipients=[email_id],\\\
    
    JMNY....        body=body,
            html=html
        )

        mail.send(msg)

        return {
            "message": "User registered successfully! Use the verification link to activate account.",
            "verification_link": verification_link,
            "token": token
        }, 201


api.add_resource(RegisterAPI, "/api/register", endpoint="registerapi")
csrf.exempt(app.view_functions['registerapi'])


class VerifyEmailAPI(Resource):
    def get(self, token: str):
        try:
            data = decode_verification_token(token)
            email_id = data.get("email_id")
            user = Users.query.filter_by(email_id=email_id).first()
            if user:
                user.is_verified = True
                db.session.commit()
                return f"Email {email_id} verified successfully!", 200
            return {'message': 'User not found.'}, 404

        except jwt.ExpiredSignatureError:
            return {'message': 'Verification link expired'}, 400
        except jwt.InvalidTokenError:
            return {'message': 'Invalid verification link'}, 400


api.add_resource(
    VerifyEmailAPI, "/api/verify_email/<path:token>",  endpoint="verifyemailapi")
csrf.exempt(app.view_functions['verifyemailapi'])


class LoginAPI(Resource):
    def post(self):
        data = request.get_json()
        email_id = data.get('email_id', '').strip().lower()
        password = data.get('password', '')

        if not (email_id and password):
            return {'message': 'Please provide email ID and password.'}, 400

        user = Users.query.filter_by(email_id=email_id).first()
        if not user:
            return {'message': 'User ID not registered. Please register first.'}, 404

        if not check_password_hash(user.password, password):
            return {'message': 'Incorrect password.'}, 401

        if not user.is_verified:
            return {'message': 'Email not verified. Please verify your email.'}, 403

        payload = {
            "user_id": user.id,
            "role": user.role,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }

        token = jwt.encode(
            payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")

        session['user_id'] = user.id
        session['role'] = user.role

        return {'message': 'Logged in successfully.', 'token': token, 'role': user.role}, 200


api.add_resource(LoginAPI, "/api/login", endpoint="loginapi")
csrf.exempt(app.view_functions['loginapi'])


class AdminAPI(Resource):
    @token_required(role='admin')
    def get(self):
        return {'message': 'Welcome, admin!'}, 200


app.register_blueprint(api_bp)


# ============================================================================
# 13. API ENDPOINTS
# ============================================================================


@app.route('/api/v1', methods=['GET'])
def api_root():
    """API information endpoint"""
    return jsonify({
        'name': 'Image Manipulation API',
        'version': '1.0.0',
        'description': 'AI-powered image editing API with company t-shirt application',
        'documentation': '/api/v1/docs',
        'endpoints': {
            'authentication': '/api/v1/auth',
            'images': '/api/v1/images'
        },
        'authentication_methods': [
            'API Key (X-API-Key header)',
            'JWT Token (Bearer token)'
        ]
    }), 200


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '1.0.0',
        'services': {
            'database': 'operational',
            'ai_service': 'operational' if genai_client else 'unavailable',
            'email_service': 'operational'
        }
    }), 200


@csrf.exempt
@app.route('/api/v1/images/process', methods=['POST'])
def api_process_image():
    """
    API endpoint to process images with API key authentication
    """
    # Verify API key
    api_key = request.headers.get('X-API-Key')

    if not api_key:
        return jsonify({
            'error': 'API key missing',
            'message': 'Please provide X-API-Key header'
        }), 401

    # Verify API key in database
    import hashlib
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT user_id, is_active 
            FROM api_keys 
            WHERE key_hash = ? AND is_active = 1
        ''', (key_hash,))

        result = c.fetchone()

        if not result:
            return jsonify({
                'error': 'Invalid API key',
                'message': 'The provided API key is invalid or inactive'
            }), 401

        user_id = result['user_id']

        # Update last_used and request_count
        c.execute('''
            UPDATE api_keys 
            SET last_used = ?, request_count = request_count + 1 
            WHERE key_hash = ?
        ''', (datetime.now(timezone.utc), key_hash))
        conn.commit()

    # Check if image file is present
    if 'image' not in request.files:
        return jsonify({
            'error': 'No image provided',
            'message': 'Please upload an image file'
        }), 400

    file = request.files['image']

    if file.filename == '':
        return jsonify({
            'error': 'No file selected',
            'message': 'Please select a file to upload'
        }), 400

    # Check if genai_client is available
    if not genai_client:
        return jsonify({
            'error': 'Service unavailable',
            'message': 'Image processing service is not configured'
        }), 503

    try:
        # Save uploaded file
        upload_filename = f"upload_{user_id}_{uuid.uuid4().hex}.png"
        upload_path = os.path.join(
            app.config['UPLOAD_FOLDER'], upload_filename)
        file.save(upload_path)

        # Detect face
        import cv2
        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        img = cv2.imread(upload_path)
        if img is None:
            os.remove(upload_path)
            return jsonify({
                'error': 'Invalid image',
                'message': 'Could not read the uploaded image'
            }), 400

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(
            gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
        )

        if len(faces) == 0:
            os.remove(upload_path)
            return jsonify({
                'error': 'No face detected',
                'message': 'No human face detected. Please upload a photo with a person.'
            }), 400

        # Read image bytes
        with open(upload_path, "rb") as f:
            image_bytes = f.read()

        # AI Processing
        start_time = time.time()

        prompt = """Replace ONLY the shirt/t-shirt/top that the person is wearing with the company uniform t-shirt.

CRITICAL REQUIREMENTS:
1. Preserve EVERYTHING about the person: face, skin tone, hair, facial features, body shape, pose
2. Keep the EXACT same background, lighting, and image quality
3. ONLY change the shirt/t-shirt to match the company uniform design
4. The new t-shirt must fit naturally on the person's body with correct perspective and wrinkles
5. Maintain the same pose and arm positions
6. Keep all accessories (watches, glasses, etc.) unchanged

The company t-shirt design: Black t-shirt with white circular logo that says "SUPPORT SMALL BUSINESS" in a badge/stamp style.

Apply this t-shirt design naturally to the person while preserving everything else in the image."""

        # Retry logic
        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                response = genai_client.models.generate_content(
                    model="gemini-2.5-flash-image",
                    contents=[
                        {"role": "user", "parts": [
                            {"text": prompt},
                            {"inline_data": {
                                "mime_type": "image/png", "data": image_bytes}}
                        ]}
                    ],
                    config=GenerateContentConfig(
                        response_modalities=["IMAGE"],
                        candidate_count=1,
                    ),
                )
                break

            except Exception as api_error:
                if "429" in str(api_error) or "RESOURCE_EXHAUSTED" in str(api_error):
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        retry_delay *= 2
                        continue
                    else:
                        return jsonify({
                            'error': 'API quota exceeded',
                            'message': 'Please try again in a few minutes.'
                        }), 429
                else:
                    raise

        # Save edited image
        edited_filename = f"edited_{user_id}_{uuid.uuid4().hex}.png"
        edited_path = os.path.join(
            app.config['EDITED_FOLDER'], edited_filename)

        for part in response.candidates[0].content.parts:
            if hasattr(part, "inline_data"):
                with open(edited_path, "wb") as f:
                    f.write(part.inline_data.data)

        processing_time = time.time() - start_time

        return jsonify({
            'success': True,
            'message': 'Image processed successfully',
            'original_url': f"/static/uploads/{upload_filename}",
            'edited_url': f"/static/edited/{edited_filename}",
            'processing_time': round(processing_time, 2),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200

    except Exception as e:
        print(f"Image processing error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Processing failed',
            'message': 'An error occurred while processing your image'
        }), 500


# ============================================================================
# 14. APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        super_email = os.getenv("SUPERADMIN_EMAIL")
        super_pass = os.getenv("SUPERADMIN_PASSWORD")

        if super_email and super_pass:
            existing = Users.query.filter_by(email_id=super_email).first()
            if not existing:
                hashed = generate_password_hash(super_pass)
                superadmin = Users(
                    first_name="Super",
                    last_name="Admin",
                    email_id=super_email,
                    password=hashed,
                    is_verified=True,
                    role=UserRole.SUPERADMIN.value
                )
                db.session.add(superadmin)
                db.session.commit()
                print(f"✅ Superadmin created: {super_email}")
            else:
                print(f"ℹ️ Superadmin already exists: {super_email}")
    app.run(port=5000, debug=True)
