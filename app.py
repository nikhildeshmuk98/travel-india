
import os
import re
import resend
import ssl
import time
import secrets
import logging
import hashlib
import hmac
import smtplib
import uuid
from flask import abort
from email.message import EmailMessage
from datetime import datetime, date, timedelta
from functools import wraps
from urllib.parse import quote
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import jsonify
import requests
import mysql.connector

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, abort
)

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Google login verification
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests


# =========================================================
# 1. LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

if os.getenv("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =========================================================
# 2. CONFIGURATION
# =========================================================
# =========================================================
# 2. CONFIGURATION
# =========================================================

DB_HOST = os.getenv("DB_HOST", "localhost")

DB_CONFIG = {
    "host": DB_HOST,
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "india_tourism_db"),
    "charset": "utf8mb4",
    "connection_timeout": 20
}

# Enable verified SSL only for remote database connections.
# Local XAMPP configuration remains unchanged.
if DB_HOST not in ("localhost", "127.0.0.1"):

    DB_CONFIG.update({
        "ssl_ca": os.getenv(
            "DB_SSL_CA",
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "aiven-ca.pem"
            )
        ),
        "ssl_verify_cert": True,
        "ssl_verify_identity": True
    })


GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")
GOOGLE_PLACES_API_KEY = os.getenv(
    "GOOGLE_PLACES_API_KEY",
    GOOGLE_MAPS_API_KEY
)
GOOGLE_ROUTES_API_KEY = os.getenv(
    "GOOGLE_ROUTES_API_KEY",
    GOOGLE_MAPS_API_KEY
)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

PLACES_SEARCH_URL = (
    "https://places.googleapis.com/v1/places:searchText"
)

PLACES_NEARBY_URL = (
    "https://places.googleapis.com/v1/places:searchNearby"
)

PLACES_DETAILS_URL = "https://places.googleapis.com/v1/places/"

ROUTES_URL = (
    "https://routes.googleapis.com/directions/v2:computeRoutes"
)

# Email OTP configuration
MAIL_ADDRESS = os.getenv("MAIL_ADDRESS")
MAIL_APP_PASSWORD = os.getenv("MAIL_APP_PASSWORD")
# Email OTP configuration
MAIL_ADDRESS = os.getenv("MAIL_ADDRESS")
MAIL_APP_PASSWORD = os.getenv("MAIL_APP_PASSWORD")

# Resend Email API Configuration
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.getenv(
    "RESEND_FROM_EMAIL",
    "onboarding@resend.dev"
)

OTP_EXPIRY_SECONDS = 300
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
OTP_EXPIRY_SECONDS = 300
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
# =========================================================
# 3. DATABASE CONNECTION
# =========================================================

def get_db():
    """Create a new MySQL connection."""

    return mysql.connector.connect(**DB_CONFIG)


def execute_query(query, params=None, fetchone=False, fetchall=False):
    """Execute a query and safely close its database connection."""

    connection = None
    cursor = None

    try:
        connection = get_db()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(query, params or ())

        if fetchone:
            return cursor.fetchone()

        if fetchall:
            return cursor.fetchall()

        connection.commit()
        return cursor.lastrowid

    except mysql.connector.Error as error:
        if connection:
            connection.rollback()

        logger.exception("Database error: %s", error)
        raise

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


def log_api(api_name, endpoint, status_code, response_time, error=None):
    """Save API request information to api_logs."""

    try:
        execute_query(
            """
            INSERT INTO api_logs
            (api_name, endpoint, status_code, response_time_ms, error_message)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                api_name,
                endpoint,
                status_code,
                response_time,
                str(error)[:2000] if error else None
            )
        )
    except Exception:
        logger.exception("Unable to save API log")


# =========================================================
# 4. AUTHENTICATION DECORATORS
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login first.", "warning")
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            flash("You are not authorized to access this page.", "danger")
            return redirect(url_for("dashboard"))

        return function(*args, **kwargs)

    return wrapper


def get_current_user():

    user_id = session.get("user_id")

    if not user_id:
        return None

    return execute_query(
        """
        SELECT id, full_name, email, profile_image, role, auth_provider
        FROM users
        WHERE id = %s AND is_active = 1
        """,
        (user_id,),
        fetchone=True
    )


# =========================================================
# 5. HOME PAGE
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html",
        user=get_current_user()
    )




# ==========================================
# FORGOT PASSWORD ROUTE
# ==========================================

@app.route("/forgot-password", methods=["POST"], endpoint="forgot_password")
def forgot_password():

    conn = None
    cursor = None

    try:
        # Check Resend configuration
        if not RESEND_API_KEY or not RESEND_FROM_EMAIL:
            app.logger.error("Resend email configuration is missing.")

            return jsonify({
                "success": False,
                "message": "Email service is not configured. Please try again later."
            }), 500

        # Get email from frontend
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip().lower()

        if not email or not re.fullmatch(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email
        ):
            return jsonify({
                "success": False,
                "message": "Please enter a valid registered email."
            }), 400

        # Connect to MySQL database
        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # Check whether email exists
        cursor.execute(
            "SELECT id, email FROM users WHERE email = %s",
            (email,)
        )

        user = cursor.fetchone()

        if not user:
            return jsonify({
                "success": True,
                "message": "If this email is registered, a password reset link will be sent."
            })

        # Generate secure password reset token
        serializer = URLSafeTimedSerializer(app.secret_key)

        token = serializer.dumps(
            email,
            salt="password-reset-salt"
        )

        # Create password reset URL
        reset_link = url_for(
            "reset_password",
            token=token,
            _external=True
        )

        # Prepare email content
        email_text = f"""
Hello,

We received a request to reset your Travel India account password.

Click the link below to reset your password:

{reset_link}

This link expires in 15 minutes.

If you did not request this password reset, please ignore this email.

Regards,
Travel India Team
"""

        email_html = f"""
        <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px;">

            <h2 style="color: #ff7417;">Travel India - Password Reset</h2>

            <p>Hello,</p>

            <p>
                We received a request to reset your Travel India account password.
            </p>

            <p>Click the button below to reset your password:</p>

            <a href="{reset_link}"
               style="
                   display: inline-block;
                   background-color: #ff7417;
                   color: white;
                   padding: 12px 24px;
                   text-decoration: none;
                   border-radius: 6px;
                   font-weight: bold;
               ">
                Reset Password
            </a>

            <p>
                Or copy this link into your browser:
            </p>

            <p>
                <a href="{reset_link}">{reset_link}</a>
            </p>

            <p>
                This link expires in <strong>15 minutes</strong>.
            </p>

            <p>
                If you did not request this password reset,
                please ignore this email.
            </p>

            <br>

            <p>Regards,<br><strong>Travel India Team</strong></p>

            <p>Discover India. Explore Beyond.</p>

        </div>
        """

        # Send password reset email using Resend API
        resend.api_key = RESEND_API_KEY

        response = resend.Emails.send({
            "from": RESEND_FROM_EMAIL,
            "to": [email],
            "subject": "Travel India - Password Reset",
            "text": email_text,
            "html": email_html
        })

        app.logger.info(
            "Password reset email sent successfully. Resend response: %s",
            response
        )

        return jsonify({
            "success": True,
            "message": "Password reset link sent successfully. Please check your email."
        })

    except Exception:
        app.logger.exception("Forgot password email sending failed")

        return jsonify({
            "success": False,
            "message": "Unable to send reset link. Please try again later."
        }), 500

    finally:

        if cursor is not None:
            cursor.close()

        if conn is not None and conn.is_connected():
            conn.close()

# =========================================================
# 6. USER REGISTRATION
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = (
            request.form.get("full_name")
            or request.form.get("username")
            or ""
        ).strip()

        email = request.form.get("email", "").strip().lower()

        mobile = request.form.get("mobile", "").strip()

        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        # Basic validation
        if not all([full_name, email, mobile, password, confirm_password]):
            flash("Please fill all required fields.", "danger")
            return redirect(url_for("register"))

        if len(full_name) < 3 or len(full_name) > 60:
            flash("Enter a valid full name.", "danger")
            return redirect(url_for("register"))

        if not re.fullmatch(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email
        ):
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for("register"))

        if not re.fullmatch(r"[6-9][0-9]{9}", mobile):
            flash("Enter a valid 10-digit mobile number.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        # SERVER-SIDE EMAIL VERIFICATION
        if session.get("verified_email") != email:

            flash(
                "Please verify your email using OTP before registration.",
                "danger"
            )

            return redirect(url_for("register"))

        # Check existing email
        existing_user = execute_query(
            "SELECT id FROM users WHERE email = %s",
            (email,),
            fetchone=True
        )

        if existing_user:
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for("login"))

        # Check existing mobile
        existing_mobile = execute_query(
            "SELECT id FROM users WHERE mobile = %s",
            (mobile,),
            fetchone=True
        )

        if existing_mobile:
            flash("Mobile number already registered.", "warning")
            return redirect(url_for("register"))

        # Hash password
        password_hash = generate_password_hash(password)

        # Save user
        user_id = execute_query(
            """
            INSERT INTO users
            (
                full_name,
                email,
                mobile,
                password_hash,
                auth_provider,
                role
            )
            VALUES (%s, %s, %s, %s, 'email', 'user')
            """,
            (
                full_name,
                email,
                mobile,
                password_hash
            )
        )

        # Clear OTP session
        session.pop("verified_email", None)
        session.pop("otp_email", None)
        session.pop("otp_hash", None)
        session.pop("otp_expires", None)

        # Do not automatically log in.
        # Redirect to login page after registration.

        flash(
            "Registration successful! Please login with your email and password.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template(
        "register.html",
        google_client_id=GOOGLE_CLIENT_ID
    )



@app.route("/send-otp", methods=["POST"])
def send_otp():

    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()

    if not re.fullmatch(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({
            "success": False,
            "message": "Please enter a valid email address."
        }), 400

    # Resend configuration check
    if not RESEND_API_KEY or not RESEND_FROM_EMAIL:
        return jsonify({
            "success": False,
            "message": "Resend email configuration is missing."
        }), 500

    # Existing email check
    existing_user = execute_query(
        "SELECT id FROM users WHERE email = %s",
        (email,),
        fetchone=True
    )

    if existing_user:
        return jsonify({
            "success": False,
            "message": "This email is already registered. Please login."
        }), 409

    # Resend cooldown
    if session.get("otp_email") == email:
        last_sent = session.get("otp_sent_at", 0)
        remaining = OTP_RESEND_SECONDS - (time.time() - last_sent)

        if remaining > 0:
            return jsonify({
                "success": False,
                "message": (
                    f"Please wait {int(remaining) + 1} seconds "
                    "before requesting another OTP."
                )
            }), 429

    # Generate secure six-digit OTP
    otp = f"{secrets.randbelow(900000) + 100000}"

    # Store HMAC instead of plain OTP
    otp_hash = hmac.new(
        app.secret_key.encode(),
        f"{email}:{otp}".encode(),
        hashlib.sha256
    ).hexdigest()

    email_text = f"""
Hello,

Welcome to TRAVEL INDIA!

Your email verification OTP is:

{otp}

This OTP is valid for 5 minutes.

Do not share this OTP with anyone.

Thank you,
TRAVEL INDIA TEAM
Discover India. Explore Beyond.
"""

    email_html = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #ff7417;">Welcome to TRAVEL INDIA!</h2>
        <p>Hello,</p>
        <p>Your email verification OTP is:</p>
        <h1 style="color: #ff7417; letter-spacing: 5px;">{otp}</h1>
        <p>This OTP is valid for <strong>5 minutes</strong>.</p>
        <p>Do not share this OTP with anyone.</p>
        <p>Thank you,<br><strong>TRAVEL INDIA TEAM</strong></p>
        <p>Discover India. Explore Beyond.</p>
    </div>
    """

    try:
        resend.api_key = RESEND_API_KEY

        response = resend.Emails.send({
            "from": RESEND_FROM_EMAIL,
            "to": [email],
            "subject": "Travel India - Email Verification OTP",
            "text": email_text,
            "html": email_html
        })

        # Store OTP only after successful email API response
        session["otp_email"] = email
        session["otp_hash"] = otp_hash
        session["otp_expires"] = time.time() + OTP_EXPIRY_SECONDS
        session["otp_sent_at"] = time.time()
        session["otp_attempts"] = 0

        session.pop("verified_email", None)

        logger.info("OTP email sent successfully. Resend response: %s", response)

        return jsonify({
            "success": True,
            "message": "OTP sent successfully. Please check your email."
        })

    except Exception:
        logger.exception("Resend OTP email sending failed")

        return jsonify({
            "success": False,
            "message": "Unable to send OTP. Please check Resend settings."
        }), 500

# =========================================================
# 6B. VERIFY EMAIL OTP
# =========================================================

@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()

    otp = data.get("otp", "").strip()

    if not email or not re.fullmatch(r"\d{6}", otp):

        return jsonify({
            "success": False,
            "message": "Enter a valid six-digit OTP."
        }), 400

    # Check requested email
    if session.get("otp_email") != email:

        return jsonify({
            "success": False,
            "message": "Please request a new OTP."
        }), 400

    # Check expiry
    if time.time() > session.get("otp_expires", 0):

        session.pop("otp_hash", None)
        session.pop("otp_email", None)
        session.pop("otp_expires", None)

        return jsonify({
            "success": False,
            "message": "OTP expired. Please request a new OTP."
        }), 400

    # Attempt limit
    attempts = session.get("otp_attempts", 0)

    if attempts >= OTP_MAX_ATTEMPTS:

        session.pop("otp_hash", None)
        session.pop("otp_email", None)
        session.pop("otp_expires", None)

        return jsonify({
            "success": False,
            "message": "Maximum OTP attempts reached. Request a new OTP."
        }), 429

    # Generate HMAC for entered OTP
    entered_hash = hmac.new(
        app.secret_key.encode(),
        f"{email}:{otp}".encode(),
        hashlib.sha256
    ).hexdigest()

    stored_hash = session.get("otp_hash", "")

    # Compare OTP securely
    if not stored_hash or not hmac.compare_digest(
        entered_hash,
        stored_hash
    ):

        session["otp_attempts"] = attempts + 1

        return jsonify({
            "success": False,
            "message": "Incorrect OTP. Please try again."
        }), 400

    # Successful verification
    session["verified_email"] = email

    session.pop("otp_hash", None)
    session.pop("otp_expires", None)
    session.pop("otp_attempts", None)

    return jsonify({
        "success": True,
        "message": "Email verified successfully!"
    })

# =========================================================
# 7. USER LOGIN
# =========================================================


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Enter your email and password.", "danger")
            return redirect(url_for("login"))

        try:
            user = execute_query(
                """
                SELECT *
                FROM users
                WHERE email = %s AND is_active = 1
                """,
                (email,),
                fetchone=True
            )

            if not user or not user.get("password_hash"):
                flash("Invalid email or password.", "danger")
                return redirect(url_for("login"))

            if not check_password_hash(user["password_hash"], password):
                flash("Invalid email or password.", "danger")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]

            flash("Login successful!", "success")

            if user["role"] == "admin":
                return redirect(url_for("admin"))

            return redirect(url_for("dashboard"))

        except Exception:
            logger.exception("Email login failed")
            flash("Something went wrong. Please try again.", "danger")
            return redirect(url_for("login"))

    return render_template(
        "login.html",
        google_client_id=GOOGLE_CLIENT_ID
    )

# =========================================================
# 8. GOOGLE LOGIN
# =========================================================

@app.route("/google-login", methods=["POST"])
def google_login():

    if not GOOGLE_CLIENT_ID:
        return jsonify({
            "success": False,
            "message": "Google authentication is not configured."
        }), 500

    data = request.get_json(silent=True) or {}
    credential = data.get("credential")

    if not credential:
        return jsonify({
            "success": False,
            "message": "Google credential is missing."
        }), 400

    try:

        google_user = id_token.verify_oauth2_token(
            credential,
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )

        email = google_user.get("email", "").lower()
        google_id = google_user.get("sub")
        full_name = google_user.get("name", "Google User")
        picture = google_user.get("picture")

        if not email or not google_id or not google_user.get("email_verified"):
            return jsonify({
                "success": False,
                "message": "Google email verification failed."
            }), 401

        user = execute_query(
            "SELECT * FROM users WHERE email = %s",
            (email,),
            fetchone=True
        )

        if user:

            if not user["is_active"]:
                return jsonify({
                    "success": False,
                    "message": "Your account is inactive."
                }), 403

            if user["google_id"] and user["google_id"] != google_id:
                return jsonify({
                    "success": False,
                    "message": "Google account does not match."
                }), 403

            execute_query(
                """
                UPDATE users
                SET google_id = %s,
                    profile_image = COALESCE(
                    NULLIF(profile_image, ''),
                      %s
                      )
                WHERE id = %s
                """,
                (google_id, picture, user["id"])
            )

            user_id = user["id"]
            role = user["role"]

        else:

            user_id = execute_query(
                """
                INSERT INTO users
                (full_name, email, google_id, profile_image,
                 auth_provider, role)
                VALUES (%s, %s, %s, %s, 'google', 'user')
                """,
                (full_name, email, google_id, picture)
            )

            role = "user"

        session.clear()
        session["user_id"] = user_id
        session["role"] = role
        session["full_name"] = full_name

        return jsonify({
            "success": True,
            "redirect": (
                url_for("admin") if role == "admin"
                else url_for("dashboard")
            )
        })

    except ValueError:
        return jsonify({
            "success": False,
            "message": "Invalid Google login token."
        }), 401

    except Exception:
        logger.exception("Google login failed")

        return jsonify({
            "success": False,
            "message": "Google login failed. Please try again."
        }), 500


# =========================================================
# 9. LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()
    flash("You have been logged out.", "success")

    return redirect(url_for("index"))


# =========================================================
# 10. USER DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user = get_current_user()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    states = execute_query(
        "SELECT * FROM states ORDER BY state_name",
        fetchall=True
    )

    recent_searches = execute_query(
        """
        SELECT sh.*, s.state_name, d.district_name
        FROM search_history sh
        LEFT JOIN states s ON sh.state_id = s.id
        LEFT JOIN districts d ON sh.district_id = d.id
        WHERE sh.user_id = %s
        ORDER BY sh.created_at DESC
        LIMIT 5
        """,
        (user["id"],),
        fetchall=True
    )

    wishlist_count = execute_query(
        "SELECT COUNT(*) AS total FROM wishlist WHERE user_id = %s",
        (user["id"],),
        fetchone=True
    )

    trips_count = execute_query(
        "SELECT COUNT(*) AS total FROM trips WHERE user_id = %s",
        (user["id"],),
        fetchone=True
    )

    return render_template(
        "dashboard.html",
        user=user,
        states=states,
        recent_searches=recent_searches,
        wishlist_count=wishlist_count["total"],
        trips_count=trips_count["total"]
    )


# =========================================================
# 11. GET DISTRICTS FOR A STATE
# =========================================================

@app.route("/api/districts/<int:state_id>")
@login_required
def get_districts(state_id):

    districts = execute_query(
        """
        SELECT id, district_name, latitude, longitude
        FROM districts
        WHERE state_id = %s
        ORDER BY district_name
        """,
        (state_id,),
        fetchall=True
    )

    return jsonify({
        "success": True,
        "districts": districts
    })






# =========================================================
# 12. FREE OPENSTREETMAP TOURIST PLACES SEARCH
# =========================================================

def google_places_text_search(
    query,
    latitude=None,
    longitude=None,
    radius_km=25,
    page_token=None
):
    """
    Discover tourist attractions using:
    1. Nominatim - Free geocoding
    2. Overpass API - Free tourist place discovery
    3. OpenStreetMap - Location information

    Features:
    - Short network timeouts
    - Multiple Overpass fallback servers
    - Duplicate place-name removal
    - Safe handling of API failures
    - Frontend-compatible response structure
    """

    import re
    import requests

    OVERPASS_URLS = [
        "https://overpass-api.de/api/interpreter",
        "https://overpass.kumi.systems/api/interpreter",
        "https://overpass.private.coffee/api/interpreter"
    ]

    NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"

    headers = {
        "User-Agent": "TravelIndiaTourismApp/1.0 (tourism discovery)",
        "Accept": "application/json"
    }

    EMPTY_RESULT = {
        "places": [],
        "nextPageToken": None
    }

    # -----------------------------------------------------
    # 1. VALIDATE SEARCH RADIUS
    # -----------------------------------------------------

    try:
        radius_km = int(radius_km)
    except (TypeError, ValueError):
        raise ValueError("Invalid search radius.")

    if radius_km not in [5, 10, 25, 50, 100]:
        raise ValueError("Invalid search radius.")

    radius_meters = radius_km * 1000

    # -----------------------------------------------------
    # 2. GET LOCATION COORDINATES
    # -----------------------------------------------------

    if latitude is None or longitude is None:

        location_query = (
            str(query or "")
            .replace("Tourist attractions in", "")
            .strip()
        )

        if not location_query:
            raise ValueError("District name is missing.")

        # Add India only when it is not already present.
        # Do not force Andhra Pradesh for other states.
        if "india" not in location_query.lower():
            location_query += ", India"

        logger.info(
            "Geocoding location: %s",
            location_query
        )

        try:

            geocode_response = requests.get(
                NOMINATIM_URL,
                params={
                    "q": location_query,
                    "format": "jsonv2",
                    "limit": 5,
                    "countrycodes": "in",
                    "addressdetails": 1
                },
                headers=headers,
                timeout=(2, 5)
            )

            geocode_response.raise_for_status()

            geocode_results = geocode_response.json()

        except (
            requests.RequestException,
            ValueError
        ) as error:

            logger.warning(
                "Nominatim geocoding failed: %s",
                error
            )

            return EMPTY_RESULT

        if not geocode_results:

            logger.warning(
                "Nominatim could not find: %s",
                location_query
            )

            return EMPTY_RESULT

        # Prefer administrative / district-level results.
        selected_location = geocode_results[0]

        for result in geocode_results:

            result_type = (
                str(result.get("type", "")).lower()
                + " "
                + str(result.get("class", "")).lower()
            )

            if any(
                word in result_type
                for word in [
                    "administrative",
                    "district",
                    "county"
                ]
            ):

                selected_location = result
                break

        try:

            latitude = float(selected_location["lat"])
            longitude = float(selected_location["lon"])

        except (KeyError, TypeError, ValueError):

            logger.warning(
                "Invalid coordinates returned by Nominatim."
            )

            return EMPTY_RESULT

        logger.info(
            "Geocoded location successfully: %s, %s",
            latitude,
            longitude
        )

    else:

        try:
            latitude = float(latitude)
            longitude = float(longitude)

        except (TypeError, ValueError):

            raise ValueError("Invalid location coordinates.")

    # -----------------------------------------------------
    # 3. VALIDATE COORDINATES
    # -----------------------------------------------------

    if not (-90 <= latitude <= 90):
        raise ValueError("Invalid latitude.")

    if not (-180 <= longitude <= 180):
        raise ValueError("Invalid longitude.")

    # -----------------------------------------------------
    # 4. BUILD OVERPASS QUERY
    # -----------------------------------------------------

    overpass_query = f"""
    [out:json][timeout:15];

    (
      nwr(around:{radius_meters},{latitude},{longitude})["tourism"];
      nwr(around:{radius_meters},{latitude},{longitude})["historic"];
      nwr(around:{radius_meters},{latitude},{longitude})["leisure"="park"];
      nwr(around:{radius_meters},{latitude},{longitude})["natural"~"waterfall|beach|cave_entrance|peak|spring|lake"];
      nwr(around:{radius_meters},{latitude},{longitude})["amenity"="place_of_worship"];
      nwr(around:{radius_meters},{latitude},{longitude})["waterway"="waterfall"];
      nwr(around:{radius_meters},{latitude},{longitude})["man_made"="monument"];
      nwr(around:{radius_meters},{latitude},{longitude})["landuse"="recreation_ground"];
    );

    out center tags;
    """

    osm_data = None
    last_error = None

    # -----------------------------------------------------
    # 5. TRY OVERPASS SERVERS WITH SHORT TIMEOUTS
    # -----------------------------------------------------

    for overpass_url in OVERPASS_URLS:

        try:

            logger.info(
                "Trying Overpass server: %s",
                overpass_url
            )

            response = requests.post(
                overpass_url,
                data={
                    "data": overpass_query
                },
                headers=headers,
                timeout=(2, 4)
            )

            response.raise_for_status()

            osm_data = response.json()

            if not isinstance(osm_data, dict):
                raise ValueError(
                    "Invalid Overpass response format."
                )

            if "elements" not in osm_data:
                raise ValueError(
                    "Overpass response has no elements."
                )

            logger.info(
                "Overpass request successful: %s",
                overpass_url
            )

            break

        except (
            requests.RequestException,
            ValueError
        ) as error:

            last_error = error

            logger.warning(
                "Overpass server failed: %s | %s",
                overpass_url,
                error
            )

            continue

    # -----------------------------------------------------
    # 6. HANDLE ALL SERVER FAILURES SAFELY
    # -----------------------------------------------------

    if osm_data is None:

        logger.error(
            "All Overpass servers failed. Last error: %s",
            last_error
        )

        # Do not crash the complete Flask route.
        return EMPTY_RESULT

    # -----------------------------------------------------
    # 7. NORMALIZE OSM RESULTS
    # -----------------------------------------------------

    elements = osm_data.get("elements", [])

    places = []

    # Remove repeated names, ignoring case and extra spaces.
    seen_place_names = set()

    for element in elements:

        tags = element.get("tags", {})

        if not isinstance(tags, dict):
            continue

        place_name = (
            tags.get("name:en")
            or tags.get("name")
            or tags.get("official_name")
            or tags.get("short_name")
        )

        if not place_name:
            continue

        place_name = str(place_name).strip()

        if not place_name:
            continue

        # Normalize name for duplicate detection.
        normalized_name = re.sub(
            r"\s+",
            " ",
            place_name.casefold()
        ).strip()

        if normalized_name in seen_place_names:
            continue

        # -------------------------------------------------
        # GET PLACE COORDINATES
        # -------------------------------------------------

        element_type = element.get("type")

        if element_type == "node":

            place_latitude = element.get("lat")
            place_longitude = element.get("lon")

        else:

            center = element.get("center", {})

            place_latitude = center.get("lat")
            place_longitude = center.get("lon")

        if (
            place_latitude is None
            or place_longitude is None
        ):
            continue

        try:

            place_latitude = float(place_latitude)
            place_longitude = float(place_longitude)

        except (TypeError, ValueError):

            continue

        if not (
            -90 <= place_latitude <= 90
            and -180 <= place_longitude <= 180
        ):
            continue

        # Mark name as seen only after validating coordinates.
        seen_place_names.add(normalized_name)

        # -------------------------------------------------
        # PLACE CATEGORY
        # -------------------------------------------------

        category = (
            tags.get("tourism")
            or tags.get("historic")
            or tags.get("leisure")
            or tags.get("natural")
            or tags.get("amenity")
            or tags.get("waterway")
            or tags.get("man_made")
            or "tourist_attraction"
        )

        # -------------------------------------------------
        # FORMATTED ADDRESS
        # -------------------------------------------------

        formatted_address = ", ".join(
            str(part)
            for part in [
                tags.get("addr:housenumber"),
                tags.get("addr:street"),
                tags.get("addr:suburb"),
                (
                    tags.get("addr:city")
                    or tags.get("addr:town")
                    or tags.get("addr:village")
                ),
                tags.get("addr:district"),
                tags.get("addr:state"),
                tags.get("addr:country")
            ]
            if part
        )

        if not formatted_address:

            formatted_address = (
                str(query or "")
                .replace("Tourist attractions in", "")
                .strip()
            )

        # -------------------------------------------------
        # MAP URLS
        # -------------------------------------------------

        map_url = (
            "https://www.openstreetmap.org/"
            f"?mlat={place_latitude}"
            f"&mlon={place_longitude}"
            f"#map=16/{place_latitude}/{place_longitude}"
        )

        osm_url = (
            "https://www.openstreetmap.org/"
            f"{element_type}/{element['id']}"
        )

        # -------------------------------------------------
        # TOURIST RELEVANCE SCORE
        # -------------------------------------------------

        tourism_value = tags.get("tourism", "")
        historic_value = tags.get("historic", "")

        priority = 0

        if tourism_value in [
            "attraction",
            "museum",
            "viewpoint",
            "zoo",
            "theme_park",
            "artwork"
        ]:
            priority += 10

        if historic_value in [
            "monument",
            "fort",
            "castle",
            "archaeological_site",
            "temple"
        ]:
            priority += 8

        if tags.get("amenity") == "place_of_worship":
            priority += 5

        if tags.get("natural") in [
            "waterfall",
            "beach",
            "cave_entrance",
            "peak",
            "lake"
        ]:
            priority += 5

        # -------------------------------------------------
        # BUILD FRONTEND-COMPATIBLE PLACE OBJECT
        # -------------------------------------------------

        place_id = f"{element_type}_{element['id']}"

        places.append({

            "id": place_id,

            "name": place_name,

            "displayName": {
                "text": place_name
            },

            "formattedAddress": formatted_address,

            "location": {
                "latitude": place_latitude,
                "longitude": place_longitude
            },

            "lat": place_latitude,
            "lon": place_longitude,

            "primaryType": category,
            "types": [category],
            "category": category,

            "priority": priority,

            "rating": None,
            "userRatingCount": 0,

            "photos": [],

            "googleMapsUri": map_url,
            "osm_url": osm_url,

            "websiteUri": (
                tags.get("website")
                or tags.get("contact:website")
            ),

            "nationalPhoneNumber": (
                tags.get("phone")
                or tags.get("contact:phone")
            ),

            "regularOpeningHours": {
                "weekdayDescriptions": (
                    [tags["opening_hours"]]
                    if tags.get("opening_hours")
                    else []
                )
            },

            "source": "OpenStreetMap"

        })

    # -----------------------------------------------------
    # 8. SORT BY TOURIST RELEVANCE
    # -----------------------------------------------------

    places.sort(
        key=lambda place: (
            -place["priority"],
            place["name"].casefold()
        )
    )

    # Limit results.
    places = places[:200]

    logger.info(
        "OSM search completed | Places: %s | Coordinates: %s, %s | Radius: %s km",
        len(places),
        latitude,
        longitude,
        radius_km
    )

    # -----------------------------------------------------
    # 9. RETURN RESULTS
    # -----------------------------------------------------

    return {
        "places": places,
        "nextPageToken": None
    }


# =========================================================
# 13. TOURIST PLACES SEARCH - FLASK + OPENSTREETMAP
# =========================================================

@app.route("/tourist-places", methods=["GET", "POST"])
@login_required
def tourist_places():

    import re

    # -----------------------------------------------------
    # HELPER 1: FORMAT AND VALIDATE TOURIST PLACES
    # -----------------------------------------------------

    def format_places(osm_places):

        formatted_places = []

        # Avoid duplicate tourist place names.
        seen_names = set()

        for place in osm_places or []:

            if not isinstance(place, dict):
                continue

            location = place.get("location") or {}

            if not isinstance(location, dict):
                location = {}

            latitude = (
                location.get("latitude")
                if location.get("latitude") is not None
                else place.get("lat")
            )

            longitude = (
                location.get("longitude")
                if location.get("longitude") is not None
                else place.get("lon")
            )

            # Validate coordinates.
            try:

                latitude = float(latitude)
                longitude = float(longitude)

                if not (-90 <= latitude <= 90):
                    continue

                if not (-180 <= longitude <= 180):
                    continue

            except (TypeError, ValueError):
                continue

            # Get display name.
            display_name = place.get("displayName") or {}

            if isinstance(display_name, dict):
                display_name = display_name.get("text", "")

            name = (
                place.get("name")
                or display_name
                or "Tourist Destination"
            )

            name = str(name).strip()

            if not name or name == "Tourist Destination":
                continue

            # Normalize names for duplicate detection.
            normalized_name = re.sub(
                r"\s+",
                " ",
                name.casefold()
            ).strip()

            if normalized_name in seen_names:
                continue

            seen_names.add(normalized_name)

            # Address.
            address = (
                place.get("formattedAddress")
                or place.get("address")
                or "Location details unavailable"
            )

            # Category.
            category = (
                place.get("primaryType")
                or place.get("category")
                or "tourist_attraction"
            )

            # Description.
            description = (
                place.get("description")
                or f"Explore {name}, a beautiful destination in India."
            )

            formatted_places.append({

                **place,

                # Frontend-compatible fields.
                "place_id": (
                    place.get("id")
                    or place.get("place_id")
                ),

                "name": name,

                "address": address,

                "description": description,

                "latitude": latitude,

                "longitude": longitude,

                "category": category,

                "photo_name": place.get("photo_name")

            })

        return formatted_places

    # -----------------------------------------------------
    # HELPER 2: CREATE STATE SLUG
    # -----------------------------------------------------

    def create_slug(value):

        value = str(value or "").strip().lower()

        slug = ""

        for character in value:

            if character.isalnum():
                slug += character

            elif character in [" ", "-", "_"]:
                slug += "-"

        while "--" in slug:
            slug = slug.replace("--", "-")

        return slug.strip("-")

    # -----------------------------------------------------
    # HELPER 3: BUILD ERROR MESSAGE
    # -----------------------------------------------------

    def get_search_error_message(error):

        logger.exception(
            "Tourist places search error: %s",
            error
        )

        if isinstance(error, requests.Timeout):

            return (
                "Tourist places server is taking too long "
                "to respond. Please try again."
            )

        if isinstance(error, requests.RequestException):

            return (
                "Unable to connect to the OpenStreetMap "
                "servers. Please try again."
            )

        return (
            "Something went wrong while loading "
            "tourist destinations."
        )

    # -----------------------------------------------------
    # HELPER 4: VALIDATE DISTRICT COORDINATES
    # -----------------------------------------------------

    def get_valid_coordinates(latitude, longitude):

        if latitude is None or longitude is None:
            return None, None

        try:

            latitude = float(latitude)
            longitude = float(longitude)

            if not (-90 <= latitude <= 90):
                return None, None

            if not (-180 <= longitude <= 180):
                return None, None

            return latitude, longitude

        except (TypeError, ValueError):

            return None, None

    # =====================================================
    # GET REQUEST - LOAD SELECTED DISTRICT PAGE
    # =====================================================

    if request.method == "GET":

        district_id = request.args.get("district")

        district_name = ""
        state_name = ""

        state_slug = ""
        video_slug = ""

        places = []
        api_error = None

        top_attractions = 0
        best_places = 0

        user = get_current_user()

        # ---------------------------------------------
        # VALIDATE DISTRICT ID
        # ---------------------------------------------

        if not district_id:

            api_error = (
                "Please select a district to explore tourist places."
            )

        else:

            try:

                district_id = int(district_id)

                if district_id <= 0:
                    raise ValueError("Invalid district ID.")

                # -------------------------------------
                # FETCH DISTRICT AND STATE
                # -------------------------------------

                district = execute_query(
                    """
                    SELECT
                        d.id,
                        d.district_name,
                        d.state_id,
                        d.latitude,
                        d.longitude,
                        s.state_name
                    FROM districts d
                    INNER JOIN states s
                        ON d.state_id = s.id
                    WHERE d.id = %s
                    """,
                    (district_id,),
                    fetchone=True
                )

                if not district:

                    api_error = (
                        "Selected district was not found."
                    )

                else:

                    district_name = district["district_name"]

                    state_name = district["state_name"]

                    state_slug = create_slug(state_name)

                    video_slug = state_slug

                    # ---------------------------------
                    # GET DISTRICT COORDINATES
                    # ---------------------------------

                    latitude, longitude = get_valid_coordinates(
                        district.get("latitude"),
                        district.get("longitude")
                    )

                    # ---------------------------------
                    # BUILD SEARCH QUERY
                    # ---------------------------------

                    search_query = (
                        f"Tourist attractions in "
                        f"{district_name}, "
                        f"{state_name}, India"
                    )

                    logger.info(
                        "Loading tourist places for %s, %s",
                        district_name,
                        state_name
                    )

                    # ---------------------------------
                    # SEARCH OPENSTREETMAP
                    # ---------------------------------

                    try:

                        result = google_places_text_search(
                            query=search_query,
                            latitude=latitude,
                            longitude=longitude,
                            radius_km=25
                        )

                        if not isinstance(result, dict):

                            raise ValueError(
                                "Invalid OpenStreetMap response."
                            )

                        osm_places = result.get("places", [])

                        if not isinstance(osm_places, list):

                            raise ValueError(
                                "Invalid tourist places data."
                            )

                        places = format_places(osm_places)

                        # ---------------------------------
                        # PAGE STATISTICS
                        # ---------------------------------

                        top_attractions = len(places)

                        best_places = len(places)

                        logger.info(
                            "Tourist places loaded | "
                            "District: %s | Places: %s",
                            district_name,
                            len(places)
                        )

                        if not places:

                            api_error = (
                                "No tourist places were found "
                                "in this area. Please try a "
                                "larger search radius."
                            )

                    except Exception as error:

                        api_error = get_search_error_message(error)

            except (ValueError, TypeError):

                api_error = "Invalid district selected."

            except Exception as error:

                api_error = get_search_error_message(error)

        # ---------------------------------------------
        # RENDER TOURIST PLACES PAGE
        # ---------------------------------------------

        return render_template(
            "tourist_places.html",

            user=user,

            district_name=district_name,

            state_name=state_name,

            state_slug=state_slug,

            video_slug=video_slug,

            top_attractions=top_attractions,

            best_places=best_places,

            places=places,

            api_error=api_error
        )

    # =====================================================
    # POST REQUEST - SEARCH TOURIST PLACES
    # =====================================================

    data = request.get_json(silent=True) or request.form

    search_mode = str(
        data.get("search_mode", "district")
    ).strip().lower()

    # -----------------------------------------------------
    # VALIDATE SEARCH RADIUS
    # -----------------------------------------------------

    try:

        radius_km = int(
            data.get("radius_km", 25)
        )

    except (ValueError, TypeError):

        return jsonify({
            "success": False,
            "message": "Please select a valid search radius."
        }), 400

    if radius_km not in [5, 10, 25, 50, 100]:

        return jsonify({
            "success": False,
            "message": "Invalid search radius."
        }), 400

    state_id = None
    district_id = None

    latitude = None
    longitude = None

    search_query = ""

    # =====================================================
    # DISTRICT SEARCH
    # =====================================================

    if search_mode == "district":

        district_id = data.get("district_id")

        if not district_id:

            return jsonify({
                "success": False,
                "message": "Please select a district."
            }), 400

        try:

            district_id = int(district_id)

            if district_id <= 0:
                raise ValueError("Invalid district ID.")

        except (ValueError, TypeError):

            return jsonify({
                "success": False,
                "message": "Invalid district selected."
            }), 400

        # ---------------------------------------------
        # FETCH DISTRICT INFORMATION
        # ---------------------------------------------

        try:

            district = execute_query(
                """
                SELECT
                    d.id,
                    d.district_name,
                    d.state_id,
                    d.latitude,
                    d.longitude,
                    s.state_name
                FROM districts d
                INNER JOIN states s
                    ON d.state_id = s.id
                WHERE d.id = %s
                """,
                (district_id,),
                fetchone=True
            )

        except Exception as error:

            logger.exception(
                "Failed to fetch district information."
            )

            return jsonify({
                "success": False,
                "message": "Unable to load district information."
            }), 500

        if not district:

            return jsonify({
                "success": False,
                "message": "District not found."
            }), 404

        state_id = district["state_id"]

        latitude, longitude = get_valid_coordinates(
            district.get("latitude"),
            district.get("longitude")
        )

        search_query = (
            f"Tourist attractions in "
            f"{district['district_name']}, "
            f"{district['state_name']}, India"
        )

    # =====================================================
    # CURRENT LOCATION SEARCH
    # =====================================================

    elif search_mode == "current_location":

        latitude = data.get("latitude")

        longitude = data.get("longitude")

        if latitude is None or longitude is None:

            return jsonify({
                "success": False,
                "message": "Current location is required."
            }), 400

        try:

            latitude = float(latitude)

            longitude = float(longitude)

        except (ValueError, TypeError):

            return jsonify({
                "success": False,
                "message": "Invalid location coordinates."
            }), 400

        if not (-90 <= latitude <= 90):

            return jsonify({
                "success": False,
                "message": "Invalid latitude value."
            }), 400

        if not (-180 <= longitude <= 180):

            return jsonify({
                "success": False,
                "message": "Invalid longitude value."
            }), 400

        search_query = "Tourist attractions"

    else:

        return jsonify({
            "success": False,
            "message": "Invalid search mode."
        }), 400

    # =====================================================
    # SEARCH USING OPENSTREETMAP
    # =====================================================

    try:

        result = google_places_text_search(
            query=search_query,
            latitude=latitude,
            longitude=longitude,
            radius_km=radius_km
        )

        if not isinstance(result, dict):

            raise ValueError(
                "Invalid OpenStreetMap response."
            )

        osm_places = result.get("places", [])

        if not isinstance(osm_places, list):

            raise ValueError(
                "Invalid tourist places response."
            )

        # ---------------------------------------------
        # FORMAT AND REMOVE DUPLICATES
        # ---------------------------------------------

        places = format_places(osm_places)

        next_page_token = result.get("nextPageToken")

        # ---------------------------------------------
        # SAVE SEARCH HISTORY
        # ---------------------------------------------

        try:

            execute_query(
                """
                INSERT INTO search_history
                (
                    user_id,
                    state_id,
                    district_id,
                    search_mode,
                    search_latitude,
                    search_longitude,
                    radius_km
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    session["user_id"],
                    state_id,
                    district_id,
                    search_mode,
                    latitude,
                    longitude,
                    radius_km
                )
            )

        except Exception:

            # Search results should still be returned
            # even if saving history fails.

            logger.exception(
                "Unable to save tourist search history."
            )

        # ---------------------------------------------
        # RETURN JSON RESPONSE
        # ---------------------------------------------

        return jsonify({

            "success": True,

            "message": (
                "Tourist places found successfully."
                if places
                else "No tourist places found for this location."
            ),

            "places": places,

            "next_page_token": next_page_token,

            "count": len(places)

        }), 200

    except Exception as error:

        logger.exception(
            "OpenStreetMap POST search failed."
        )

        if isinstance(error, requests.Timeout):

            status_code = 504

            message = (
                "The tourist places server took too long "
                "to respond. Please try again."
            )

        elif isinstance(error, requests.RequestException):

            status_code = 502

            message = (
                "Unable to connect to OpenStreetMap servers."
            )

        else:

            status_code = 500

            message = (
                "Something went wrong while searching "
                "tourist destinations."
            )

        return jsonify({

            "success": False,

            "message": message

        }), status_code


# =========================================================
# 14. LOAD MORE PLACES
# =========================================================


# =========================================================
# 14. LOAD MORE PLACES - OPENSTREETMAP
# =========================================================

@app.route("/api/places/load-more", methods=["POST"])
@login_required
def load_more_places():

    return jsonify({
        "success": True,
        "places": [],
        "next_page_token": None,
        "message": (
            "All available places have been loaded. "
            "OpenStreetMap search does not currently support "
            "Google-style page tokens."
        )
    }), 200


# =========================================================
# 15. PLACE DETAILS - OPENSTREETMAP
# =========================================================

@app.route("/place/<path:place_id>")
@login_required
def place_details(place_id):

    # Validate OpenStreetMap place ID
    match = re.fullmatch(r"(node|way|relation)_(\d+)", place_id)

    if not match:
        abort(400)

    osm_type = match.group(1)
    osm_id = match.group(2)

    overpass_url = "https://overpass-api.de/api/interpreter"

    query = f"""
    [out:json][timeout:30];
    {osm_type}({osm_id});
    out center tags;
    """

    try:

        start = time.time()

        response = requests.post(
            overpass_url,
            data={"data": query},
            headers={
                "User-Agent": "TravelIndiaTourismApp/1.0"
            },
            timeout=40
        )

        elapsed = int((time.time() - start) * 1000)

        log_api(
            "OpenStreetMap",
            "Place Details",
            response.status_code,
            elapsed,
            None if response.ok else response.text
        )

        response.raise_for_status()

        data = response.json()

        elements = data.get("elements", [])

        if not elements:
            flash("Place details not found.", "warning")
            return redirect(url_for("tourist_places"))

        element = elements[0]
        tags = element.get("tags", {})

        # Get coordinates
        latitude = element.get("lat")

        longitude = element.get("lon")

        if latitude is None or longitude is None:
            center = element.get("center", {})
            latitude = center.get("lat")
            longitude = center.get("lon")

        # Create a display-friendly place object
        place = {
            "id": place_id,

            "displayName": {
                "text": (
                    tags.get("name")
                    or tags.get("official_name")
                    or "Unknown Tourist Place"
                )
            },

            "formattedAddress": ", ".join(
                filter(
                    None,
                    [
                        tags.get("addr:suburb"),
                        tags.get("addr:city"),
                        tags.get("addr:district"),
                        tags.get("addr:state"),
                        tags.get("addr:country")
                    ]
                )
            ) or "Address information unavailable",

            "location": {
                "latitude": latitude,
                "longitude": longitude
            },

            "primaryType": (
                tags.get("tourism")
                or tags.get("historic")
                or tags.get("leisure")
                or "tourist_attraction"
            ),

            "types": [
                value
                for value in [
                    tags.get("tourism"),
                    tags.get("historic"),
                    tags.get("leisure"),
                    tags.get("natural")
                ]
                if value
            ],

            "websiteUri": tags.get("website"),

            "nationalPhoneNumber": tags.get("phone"),

            "internationalPhoneNumber": tags.get("contact:phone"),

            "googleMapsUri": (
                f"https://www.openstreetmap.org/{osm_type}/{osm_id}"
            ),

            "osmTags": tags,

            "rating": None,

            "userRatingCount": None,

            "photos": [],

            "reviews": [],

            "regularOpeningHours": {
                "weekdayDescriptions": [
                    tags.get("opening_hours", "Opening hours not available")
                ]
            }
        }

        return render_template(
            "place_details.html",
            place=place
        )

    except requests.RequestException:

        logger.exception("OpenStreetMap place details request failed")

        flash(
            "Unable to load place details. Please try again later.",
            "danger"
        )

        return redirect(url_for("tourist_places"))

    except (ValueError, KeyError):

        logger.exception("Invalid OpenStreetMap response")

        flash(
            "Invalid place information received.",
            "danger"
        )

        return redirect(url_for("tourist_places"))


# =========================================================
# 16. NEARBY PLACES API
# =========================================================

@app.route("/api/nearby-places", methods=["POST"])
@login_required
def nearby_places_api():

    data = request.get_json(silent=True) or {}

    latitude = data.get("latitude")
    longitude = data.get("longitude")
    category = data.get("category", "hotel")
    radius_km = int(data.get("radius_km", 10))

    allowed_categories = {
        "hotel": ["lodging"],
        "restaurant": ["restaurant"],
        "airport": ["airport"],
        "railway": ["train_station"],
        "bus": ["bus_station"],
        "hospital": ["hospital"]
    }

    if category not in allowed_categories:
        return jsonify({
            "success": False,
            "message": "Invalid category."
        }), 400

    try:

        latitude = float(latitude)
        longitude = float(longitude)

        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            raise ValueError("Invalid coordinates")

        radius_km = max(1, min(radius_km, 50))

    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "Valid location coordinates are required."
        }), 400

    if not GOOGLE_PLACES_API_KEY:
        return jsonify({
            "success": False,
            "message": "Google Places API key is not configured."
        }), 500

    headers = {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": GOOGLE_PLACES_API_KEY,
        "X-Goog-FieldMask": (
            "places.id,"
            "places.displayName,"
            "places.formattedAddress,"
            "places.location,"
            "places.rating,"
            "places.types,"
            "places.googleMapsUri"
        )
    }

    payload = {
        "includedTypes": allowed_categories[category],
        "maxResultCount": 20,
        "locationRestriction": {
            "circle": {
                "center": {
                    "latitude": latitude,
                    "longitude": longitude
                },
                "radius": radius_km * 1000
            }
        }
    }

    try:

        start = time.time()

        response = requests.post(
            PLACES_NEARBY_URL,
            headers=headers,
            json=payload,
            timeout=30
        )

        elapsed = int((time.time() - start) * 1000)

        log_api(
            "Google Places",
            "Nearby Search",
            response.status_code,
            elapsed,
            None if response.ok else response.text
        )

        response.raise_for_status()

        return jsonify({
            "success": True,
            "places": response.json().get("places", [])
        })

    except Exception:
        logger.exception("Nearby places search failed")

        return jsonify({
            "success": False,
            "message": "Unable to find nearby places."
        }), 502


# =========================================================
# 17. MAP VIEW
# =========================================================

@app.route("/map")
@login_required
def map_view():

    return render_template(
        "map_view.html",
        google_maps_api_key=GOOGLE_MAPS_API_KEY
    )


# =========================================================
# 18. GOOGLE ROUTES - DIRECTIONS
# =========================================================

@app.route("/api/directions", methods=["POST"])
@login_required
def directions_api():

    data = request.get_json(silent=True) or {}

    origin_lat = data.get("origin_lat")
    origin_lng = data.get("origin_lng")
    destination_lat = data.get("destination_lat")
    destination_lng = data.get("destination_lng")

    travel_mode = data.get("travel_mode", "DRIVE")

    allowed_modes = ["DRIVE", "WALK", "BICYCLE", "TWO_WHEELER"]

    if travel_mode not in allowed_modes:
        return jsonify({
            "success": False,
            "message": "Invalid travel mode."
        }), 400

    try:

        origin_lat = float(origin_lat)
        origin_lng = float(origin_lng)
        destination_lat = float(destination_lat)
        destination_lng = float(destination_lng)

        coordinates = [
            (origin_lat, origin_lng),
            (destination_lat, destination_lng)
        ]

        for lat, lng in coordinates:
            if not (-90 <= lat <= 90 and -180 <= lng <= 180):
                raise ValueError("Invalid coordinates")

    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "Valid origin and destination coordinates are required."
        }), 400

    if not GOOGLE_ROUTES_API_KEY:
        return jsonify({
            "success": False,
            "message": "Google Routes API is not configured."
        }), 500

    headers = {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": GOOGLE_ROUTES_API_KEY,
        "X-Goog-FieldMask": (
            "routes.distanceMeters,"
            "routes.duration,"
            "routes.polyline.encodedPolyline,"
            "routes.legs"
        )
    }

    payload = {
        "origin": {
            "location": {
                "latLng": {
                    "latitude": origin_lat,
                    "longitude": origin_lng
                }
            }
        },
        "destination": {
            "location": {
                "latLng": {
                    "latitude": destination_lat,
                    "longitude": destination_lng
                }
            }
        },
        "travelMode": travel_mode,
        "computeAlternativeRoutes": False
    }

    try:

        start = time.time()

        response = requests.post(
            ROUTES_URL,
            headers=headers,
            json=payload,
            timeout=30
        )

        elapsed = int((time.time() - start) * 1000)

        log_api(
            "Google Routes",
            "Compute Routes",
            response.status_code,
            elapsed,
            None if response.ok else response.text
        )

        response.raise_for_status()

        result = response.json()
        routes = result.get("routes", [])

        if not routes:
            return jsonify({
                "success": False,
                "message": "No route found."
            }), 404

        route = routes[0]

        return jsonify({
            "success": True,
            "distance_meters": route.get("distanceMeters"),
            "distance_km": round(
                route.get("distanceMeters", 0) / 1000, 2
            ),
            "duration": route.get("duration"),
            "polyline": route.get("polyline", {}).get(
                "encodedPolyline"
            )
        })

    except Exception:
        logger.exception("Directions API failed")

        return jsonify({
            "success": False,
            "message": "Unable to calculate directions."
        }), 502


# =========================================================
# 19. DIRECTIONS PAGE
# =========================================================

@app.route("/directions/<path:place_id>")
@login_required
def directions_page(place_id):

    return render_template(
        "directions.html",
        place_id=place_id,
        google_maps_api_key=GOOGLE_MAPS_API_KEY
    )


# =========================================================
# 20. WISHLIST PAGE
# =========================================================

@app.route("/wishlist")
@login_required
def wishlist():

    saved_places = execute_query(
        """
        SELECT id, google_place_id, created_at
        FROM wishlist
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
        fetchall=True
    )

    return render_template(
        "wishlist.html",
        saved_places=saved_places
    )



# =========================================================
# 21. ADD WISHLIST
# =========================================================

@app.route("/api/wishlist", methods=["POST"])
@login_required
def add_wishlist():

    data = request.get_json(silent=True) or {}

    place_id = str(data.get("google_place_id", "")).strip()

    if not place_id or len(place_id) > 255:
        return jsonify({
            "success": False,
            "message": "Valid Place ID is required."
        }), 400

    try:
        existing = execute_query(
            """
            SELECT id FROM wishlist
            WHERE user_id = %s AND google_place_id = %s
            """,
            (session["user_id"], place_id),
            fetchone=True
        )

        if existing:
            return jsonify({
                "success": True,
                "message": "Place already in favourites.",
                "wishlist_id": existing["id"]
            })

        wishlist_id = execute_query(
            """
            INSERT INTO wishlist (user_id, google_place_id)
            VALUES (%s, %s)
            """,
            (session["user_id"], place_id)
        )

        return jsonify({
            "success": True,
            "message": "Place added to favourites.",
            "wishlist_id": wishlist_id
        })

    except Exception:
        logger.exception("Wishlist save failed")

        return jsonify({
            "success": False,
            "message": "Unable to save this place."
        }), 500


# =========================================================
# 22. GET USER WISHLIST
# =========================================================

@app.route("/api/wishlist", methods=["GET"])
@login_required
def get_wishlist():

    try:
        favorites = execute_query(
            """
            SELECT
                id AS wishlist_id,
                google_place_id,
                created_at
            FROM wishlist
            WHERE user_id = %s
            ORDER BY created_at DESC
            """,
            (session["user_id"],),
            fetchall=True
        )

        return jsonify({
            "success": True,
            "favorites": favorites or []
        })

    except Exception:
        logger.exception("Wishlist fetch failed")

        return jsonify({
            "success": False,
            "favorites": [],
            "message": "Unable to load favourites."
        }), 500


# =========================================================
# 23. REMOVE WISHLIST
# =========================================================

@app.route("/api/wishlist/<int:wishlist_id>", methods=["DELETE"])
@login_required
def remove_wishlist(wishlist_id):

    try:
        result = execute_query(
            """
            DELETE FROM wishlist
            WHERE id = %s AND user_id = %s
            """,
            (wishlist_id, session["user_id"])
        )

        return jsonify({
            "success": True,
            "message": "Removed from favourites."
        })

    except Exception:
        logger.exception("Wishlist removal failed")

        return jsonify({
            "success": False,
            "message": "Unable to remove this place."
        }), 500

# =========================================================
# 23. TRIP PLANNER / MY TRIPS
# =========================================================

@app.route("/my-trips", methods=["GET", "POST"])
@login_required
def my_trips():

    if request.method == "POST":

        data = request.get_json(silent=True) or request.form

        trip_name = data.get("trip_name", "").strip()
        start_date = data.get("start_date") or None
        end_date = data.get("end_date") or None

        if not trip_name:
            return jsonify({
                "success": False,
                "message": "Trip name is required."
            }), 400

        try:

            if start_date and end_date:
                start = date.fromisoformat(start_date)
                end = date.fromisoformat(end_date)

                if end < start:
                    return jsonify({
                        "success": False,
                        "message": "End date cannot be before start date."
                    }), 400

            trip_id = execute_query(
                """
                INSERT INTO trips
                (user_id, trip_name, start_date, end_date)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    session["user_id"],
                    trip_name,
                    start_date,
                    end_date
                )
            )

            if request.is_json:
                return jsonify({
                    "success": True,
                    "trip_id": trip_id,
                    "message": "Trip created successfully."
                })

            flash("Trip created successfully!", "success")
            return redirect(url_for("my_trips"))

        except ValueError:
            return jsonify({
                "success": False,
                "message": "Invalid date format."
            }), 400

    trips = execute_query(
        """
        SELECT *
        FROM trips
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
        fetchall=True
    )

    return render_template(
        "my_trips.html",
        trips=trips
    )


# =========================================================
# 24. ADD DESTINATION TO TRIP
# =========================================================

@app.route("/api/trips/<int:trip_id>/destinations", methods=["POST"])
@login_required
def add_trip_destination(trip_id):

    data = request.get_json(silent=True) or {}

    place_id = data.get("google_place_id", "").strip()

    if not place_id:
        return jsonify({
            "success": False,
            "message": "Place ID is required."
        }), 400

    trip = execute_query(
        "SELECT id FROM trips WHERE id = %s AND user_id = %s",
        (trip_id, session["user_id"]),
        fetchone=True
    )

    if not trip:
        return jsonify({
            "success": False,
            "message": "Trip not found."
        }), 404

    sequence = execute_query(
        """
        SELECT COALESCE(MAX(sequence_number), 0) + 1 AS next_sequence
        FROM trip_destinations
        WHERE trip_id = %s
        """,
        (trip_id,),
        fetchone=True
    )

    execute_query(
        """
        INSERT INTO trip_destinations
        (trip_id, google_place_id, visit_date, sequence_number)
        VALUES (%s, %s, %s, %s)
        """,
        (
            trip_id,
            place_id,
            data.get("visit_date") or None,
            sequence["next_sequence"]
        )
    )

    return jsonify({
        "success": True,
        "message": "Destination added to trip."
    })

# =========================================================
# 25. PROFILE PAGE
# =========================================================

@app.route("/profile")
@login_required
def profile():

    user = execute_query(
        """
        SELECT
            id,
            full_name,
            email,
            profile_image,
            auth_provider,
            created_at
        FROM users
        WHERE id = %s
        """,
        (session["user_id"],),
        fetchone=True
    )

    if not user:
        flash("User account not found. Please log in again.", "danger")
        abort(404)

    return render_template(
        "profile.html",
        user=user
    )


# =========================================================
# 26. UPDATE PROFILE
# =========================================================

@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():

    full_name = request.form.get("full_name", "").strip()

    # Validate name
    if not full_name:
        flash("Name cannot be empty.", "danger")
        return redirect(url_for("profile"))

    if len(full_name) > 100:
        flash("Name cannot exceed 100 characters.", "danger")
        return redirect(url_for("profile"))

    # Update existing user's name
    execute_query(
        """
        UPDATE users
        SET full_name = %s
        WHERE id = %s
        """,
        (full_name, session["user_id"])
    )

    # Update session value
    session["full_name"] = full_name

    flash("Profile updated successfully.", "success")

    return redirect(url_for("profile"))

# =========================================================
# UPLOAD PROFILE IMAGE
# =========================================================

@app.route("/profile/upload-image", methods=["POST"])
@login_required
def upload_profile_image():

    if "profile_image" not in request.files:
        return jsonify({
            "success": False,
            "message": "Please select an image."
        }), 400

    image = request.files["profile_image"]

    if not image or not image.filename:
        return jsonify({
            "success": False,
            "message": "No image selected."
        }), 400

    allowed_extensions = {"jpg", "jpeg", "png", "webp"}

    filename = secure_filename(image.filename)

    if "." not in filename:
        return jsonify({
            "success": False,
            "message": "Invalid image."
        }), 400

    extension = filename.rsplit(".", 1)[1].lower()

    if extension not in allowed_extensions:
        return jsonify({
            "success": False,
            "message": "Only JPG, PNG and WEBP are allowed."
        }), 400

    image.seek(0, os.SEEK_END)
    size = image.tell()
    image.seek(0)

    if size > 5 * 1024 * 1024:
        return jsonify({
            "success": False,
            "message": "Image must be below 5 MB."
        }), 400

    upload_folder = os.path.join(
        app.static_folder,
        "uploads",
        "profile"
    )

    os.makedirs(upload_folder, exist_ok=True)

    new_filename = f"{uuid.uuid4().hex}.{extension}"

    image.save(
        os.path.join(upload_folder, new_filename)
    )

    image_path = f"uploads/profile/{new_filename}"

    execute_query(
        """
        UPDATE users
        SET profile_image = %s
        WHERE id = %s
        """,
        (image_path, session["user_id"])
    )

    return jsonify({
        "success": True,
        "message": "Profile image uploaded successfully!",
        "image_url": url_for("static", filename=image_path)
    })


# =========================================================
# REMOVE PROFILE IMAGE
# =========================================================

@app.route("/profile/remove-image", methods=["POST"])
@login_required
def remove_profile_image():

    user = execute_query(
        """
        SELECT profile_image
        FROM users
        WHERE id = %s
        """,
        (session["user_id"],),
        fetchone=True
    )

    if not user:
        return jsonify({
            "success": False,
            "message": "User not found."
        }), 404

    old_image = user.get("profile_image")

    execute_query(
        """
        UPDATE users
        SET profile_image = NULL
        WHERE id = %s
        """,
        (session["user_id"],)
    )

    if old_image:
        upload_folder = os.path.abspath(
            os.path.join(app.static_folder, "uploads", "profile")
        )

        old_path = os.path.abspath(
            os.path.join(app.static_folder, old_image)
        )

        if (
            os.path.commonpath([upload_folder, old_path]) == upload_folder
            and os.path.isfile(old_path)
        ):
            os.remove(old_path)

    return jsonify({
        "success": True,
        "message": "Profile image removed successfully!"
    })
# =========================================================
# 27. CHANGE PASSWORD
# =========================================================

@app.route("/profile/change-password", methods=["POST"])
@login_required
def change_password():

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    user = execute_query(
        "SELECT password_hash FROM users WHERE id = %s",
        (session["user_id"],),
        fetchone=True
    )

    if not user or not user["password_hash"]:
        flash("Password change is not available for this account.", "warning")
        return redirect(url_for("profile"))

    if not check_password_hash(user["password_hash"], current_password):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("profile"))

    if len(new_password) < 8:
        flash("New password must have at least 8 characters.", "danger")
        return redirect(url_for("profile"))

    if new_password != confirm_password:
        flash("New passwords do not match.", "danger")
        return redirect(url_for("profile"))

    new_hash = generate_password_hash(new_password)

    execute_query(
        "UPDATE users SET password_hash = %s WHERE id = %s",
        (new_hash, session["user_id"])
    )

    flash("Password changed successfully.", "success")

    return redirect(url_for("profile"))


# =========================================================
# 28. ADMIN LOGIN PAGE
# =========================================================

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = execute_query(
            """
            SELECT *
            FROM users
            WHERE email = %s AND role = 'admin' AND is_active = 1
            """,
            (email,),
            fetchone=True
        )

        if user and user["password_hash"] and check_password_hash(
            user["password_hash"], password
        ):

            session.clear()
            session["user_id"] = user["id"]
            session["role"] = "admin"
            session["full_name"] = user["full_name"]

            return redirect(url_for("admin"))

        flash("Invalid admin credentials.", "danger")

    return render_template("admin.html", admin_login=True)


# =========================================================
# 29. ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
@admin_required
def admin():

    user_count = execute_query(
        "SELECT COUNT(*) AS total FROM users",
        fetchone=True
    )["total"]

    place_count = execute_query(
        "SELECT COUNT(*) AS total FROM wishlist",
        fetchone=True
    )["total"]

    trip_count = execute_query(
        "SELECT COUNT(*) AS total FROM trips",
        fetchone=True
    )["total"]

    pending_reports = execute_query(
        "SELECT COUNT(*) AS total FROM reports WHERE status = 'pending'",
        fetchone=True
    )["total"]

    recent_users = execute_query(
        """
        SELECT id, full_name, email, role, created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT 10
        """,
        fetchall=True
    )

    return render_template(
        "admin.html",
        admin_login=False,
        user_count=user_count,
        place_count=place_count,
        trip_count=trip_count,
        pending_reports=pending_reports,
        recent_users=recent_users
    )


# =========================================================
# 30. ADMIN USER MANAGEMENT
# =========================================================

@app.route("/admin/users")
@admin_required
def admin_users():

    users = execute_query(
        """
        SELECT id, full_name, email, role, is_active, created_at
        FROM users
        ORDER BY created_at DESC
        """,
        fetchall=True
    )

    return render_template(
        "admin.html",
        admin_login=False,
        users=users,
        admin_section="users"
    )


@app.route("/admin/users/<int:user_id>/status", methods=["POST"])
@admin_required
def admin_update_user_status(user_id):

    if user_id == session["user_id"]:
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("admin_users"))

    data = request.get_json(silent=True) or request.form
    is_active = 1 if str(data.get("is_active")) in ["1", "true", "True"] else 0

    execute_query(
        "UPDATE users SET is_active = %s WHERE id = %s AND role != 'admin'",
        (is_active, user_id)
    )

    flash("User status updated.", "success")

    return redirect(url_for("admin_users"))


# =========================================================
# 31. ADMIN REPORTS
# =========================================================

@app.route("/admin/reports")
@admin_required
def admin_reports():

    reports = execute_query(
        """
        SELECT r.*, u.full_name, u.email
        FROM reports r
        LEFT JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
        """,
        fetchall=True
    )

    return render_template(
        "admin.html",
        admin_login=False,
        reports=reports,
        admin_section="reports"
    )


@app.route("/api/reports", methods=["POST"])
@login_required
def submit_report():

    data = request.get_json(silent=True) or request.form

    place_id = data.get("google_place_id", "").strip()
    report_type = data.get("report_type", "").strip()
    description = data.get("description", "").strip()

    if not place_id or not report_type or not description:
        return jsonify({
            "success": False,
            "message": "All report fields are required."
        }), 400

    execute_query(
        """
        INSERT INTO reports
        (user_id, google_place_id, report_type, description)
        VALUES (%s, %s, %s, %s)
        """,
        (
            session["user_id"],
            place_id,
            report_type,
            description
        )
    )

    return jsonify({
        "success": True,
        "message": "Report submitted successfully."
    })


@app.route("/admin/reports/<int:report_id>/status", methods=["POST"])
@admin_required
def admin_update_report(report_id):

    data = request.get_json(silent=True) or request.form

    status = data.get("status")
    notes = data.get("admin_notes", "")

    allowed_statuses = [
        "pending", "reviewed", "resolved", "rejected"
    ]

    if status not in allowed_statuses:
        abort(400)

    execute_query(
        """
        UPDATE reports
        SET status = %s, admin_notes = %s
        WHERE id = %s
        """,
        (status, notes, report_id)
    )

    flash("Report updated successfully.", "success")

    return redirect(url_for("admin_reports"))


# =========================================================
# 32. ADMIN API MONITORING
# =========================================================

@app.route("/admin/api-monitor")
@admin_required
def admin_api_monitor():

    logs = execute_query(
        """
        SELECT *
        FROM api_logs
        ORDER BY created_at DESC
        LIMIT 200
        """,
        fetchall=True
    )

    return render_template(
        "admin.html",
        admin_login=False,
        logs=logs,
        admin_section="api_monitor"
    )


# =========================================================
# 33. ABOUT PAGE
# =========================================================

@app.route("/about")
def about():

    return render_template("about.html")


# =========================================================
# 34. CONTACT PAGE
# =========================================================

@app.route("/contact", methods=["GET", "POST"])
def contact():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if not all([name, email, subject, message]):
            flash("Please fill all contact fields.", "danger")
            return redirect(url_for("contact"))

        # Contact form is not stored yet.
        # Configure an email provider or add a support table
        # before claiming that messages have been delivered.

        flash(
            "Your message has been received by this demo form. "
            "Email delivery is not configured yet.",
            "info"
        )

        return redirect(url_for("contact"))

    return render_template("about.html", contact_page=True)


# =========================================================
# 35. ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(error):

    logger.exception("Internal server error: %s", error)

    return render_template("500.html"), 500


# =========================================================
# 36. DATABASE CONNECTION TEST
# =========================================================

@app.route("/health")
def health():

    try:

        result = execute_query(
            "SELECT DATABASE() AS database_name",
            fetchone=True
        )

        return jsonify({
            "success": True,
            "application": "TRAVEL INDIA",
            "database": result["database_name"],
            "message": "Application and database are connected."
        })

    except Exception:

        return jsonify({
            "success": False,
            "message": "Database connection failed."
        }), 500

@app.route("/favorites")
@app.route("/favourites")
@login_required
def favourites():

    favourite_places = []

    try:

        favourite_places = execute_query(
            """
            SELECT
                id AS wishlist_id,
                google_place_id,
                created_at
            FROM wishlist
            WHERE user_id = %s
            ORDER BY created_at DESC
            """,
            (session["user_id"],),
            fetchall=True
        ) or []

    except Exception:

        logger.exception("Unable to load favourite places")

        flash(
            "Unable to load your favourites. Please try again.",
            "danger"
        )

    return render_template(
        "favorite.html",
        favourite_places=favourite_places
    )

# =========================================================
# 37. RUN FLASK APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true"
    )
