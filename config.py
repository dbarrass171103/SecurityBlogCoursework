import base64
import os
from functools import wraps
from hashlib import scrypt
from dotenv import load_dotenv
import bcrypt
from cryptography.fernet import Fernet
from flask import Flask, url_for, redirect, flash, render_template, request
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import secrets
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_talisman import Talisman
from sqlalchemy import MetaData
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_qrcode import QRcode
from flask_login import LoginManager, UserMixin, current_user
from flask_bcrypt import Bcrypt
from security.logger import start_logger

app = Flask(__name__)

# LOAD CONFIG FROM ENV
load_dotenv("blogconfig.env")

# SECRET KEY FOR FLASK FORMS
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# DATABASE CONFIG
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_ECHO"] = os.getenv("SQLALCHEMY_ECHO", True)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS", False)

# RECAPTCHA KEYS
app.config["RECAPTCHA_PUBLIC_KEY"] = os.getenv("RECAPTCHA_PUBLIC_KEY")
app.config["RECAPTCHA_PRIVATE_KEY"] = os.getenv("RECAPTCHA_PRIVATE_KEY")

metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)

db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)

bcrypt = Bcrypt(app)


# DATABASE TABLES
class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey("users.id"))
    created = db.Column(db.DateTime, nullable=False)
    title = db.Column(db.Text, nullable=False)
    body = db.Column(db.Text, nullable=False)
    user = db.relationship("User", back_populates="posts")

    def __init__(self, title, body, userid):
        self.created = datetime.now()
        self.title = title
        self.body = body
        self.userid = userid

    def update(self, title, body):
        self.created = datetime.now()
        self.title = title
        self.body = body
        self.encrypt_post(self.user.get_encryption_key())
        db.session.commit()

    def encrypt_post(self, key):  # encrypt post for storage
        self.title = Fernet(key).encrypt(self.title.encode()).decode()
        self.body = Fernet(key).encrypt(self.body.encode()).decode()

    def decrypt_post(self, key):  # decrypt post for viewing/editing
        self.title = Fernet(key).decrypt(self.title).decode()
        self.body = Fernet(key).decrypt(self.body).decode()


# USER TABLES
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    salt = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)

    # User posts
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")

    # MFA information
    mfa_key = db.Column(db.String(32), nullable=False)
    mfa_enabled = db.Column(db.Boolean, nullable=False)

    # User role
    role = db.Column(db.String(10), nullable=False, default="end_user")

    # User Security log
    log = db.relationship("Log", back_populates='user', uselist=False)

    def __init__(self, email, firstname, lastname, phone, password, mfa_key, mfa_enabled):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = bcrypt.generate_password_hash(password).decode()  # create hashed password from given password
        self.salt = base64.b64encode(secrets.token_bytes(32)).decode()  # Generate random salt for key
        self.mfa_key = mfa_key
        self.mfa_enabled = mfa_enabled

    def verify_password(self, givenpassword):  # Check entered password against hashed password
        return bcrypt.check_password_hash(self.password, givenpassword)

    def create_log(self):  # Create a user log when registering
        new_log = Log(self.id)
        db.session.add(new_log)
        db.session.commit()

    def update_log(self, ip_address):  # update users log with new information on login
        log = self.log
        log.previous_login_date = log.latest_login_date
        log.previous_ip = log.latest_ip
        log.latest_ip = ip_address
        log.latest_login_date = datetime.now()

        db.session.commit()

    def get_encryption_key(self):  # Get users encryption key from their password and salt
        password = self.password.encode()
        salt = self.salt.encode()
        key = scrypt(password=password, salt=salt, n=2048, r=8, p=1, dklen=32)
        return base64.b64encode(key)


# LOG TABLE

class Log(db.Model):
    __tablename__ = "logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    latest_login_date = db.Column(db.DateTime, nullable=True)
    previous_login_date = db.Column(db.DateTime, nullable=True)
    latest_ip = db.Column(db.String(50), nullable=True)
    previous_ip = db.Column(db.String(50), nullable=True)

    user = db.relationship("User", back_populates="log")

    def __init__(self, user_id):
        self.user_id = user_id
        self.registration_date = datetime.now()


# DATABASE ADMINISTRATOR
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for("index")


class AdminView(ModelView):  # Parent class for PostView and UserView
    column_display_pk = True
    column_hide_backrefs = False

    def is_accessible(self):  # checks if the user is allowed to access the admin page
        if not current_user.is_authenticated:
            return False
        if current_user.role != "db_admin":
            return False
        return True

    def inaccessible_callback(self, name, **kwargs):  # If user not allowed, log it and return them to the forbidden page
        if current_user.is_authenticated:
            security_logger.warning(
                f"Unauthorized access: Email={current_user.email if current_user.is_authenticated else 'Anonymous'}, "
                f"Role={current_user.role if current_user.is_authenticated else 'None'}, "
                f"URL={request.url}, IP={request.remote_addr}")
            return render_template("errors/error.html", error_title="Forbidden",
                                   error_message="You are not authorised to access this page")
        flash("You do not have access to this page. Login to access it!", "danger")
        return redirect(url_for("accounts.login"))


class PostView(AdminView):
    column_list = ("id", "userid", "created", "title", "body", "user")


class UserView(AdminView):
    column_list = (
    "id", "email", "password", "firstname", "lastname", "phone", "mfa_key", "mfa_enabled", "posts", "role")


admin = Admin(app, name="DB Admin")
admin._menu = admin._menu[1:]
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True
admin.add_link(MainIndexLink(name="Home Page"))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))

# SECURITY LOGGER

security_logger = start_logger()

# RATE LIMITING

daily_limit = "500/day"

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[daily_limit],
)

# QRCODE SETUP
qrcode = QRcode(app)

# LOGIN MANAGER
login_manager = LoginManager()
login_manager.login_view = "accounts.login"
login_manager.login_message = "You must be logged in to view this page"
login_manager.login_message_category = "info"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


def roles_required(role): # Custom decorator to allow access to pages for certain users
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                security_logger.warning(
                    f"Unauthorized access: Email={current_user.email if current_user.is_authenticated else 'Anonymous'}, "
                    f"Role={current_user.role if current_user.is_authenticated else 'None'}, "
                    f"URL={request.url}, IP={request.remote_addr}")

                return render_template("errors/error.html", error_title="Forbidden",
                                       error_message="You are not authorised to access this page")
            return func(*args, **kwargs)

        return wrapper

    return decorator


# TALISMAN SETUP

csp = {"default-src": ["'self'"],
       "img-src": ["'self'", "data:"],
       "script-src": ["'self'", "https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js",
                      "https://www.google.com/recaptcha/", "https://www.gstatic.com/recaptcha/"],
       "style-src": ["'self'", "https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css"],
       "frame-src": ["'self'", "https://www.google.com/recaptcha/", "https://recaptcha.google.com/recaptcha/"]}

talisman = Talisman(app, content_security_policy=csp)
# IMPORT BLUEPRINTS

from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp

# REGISTER BLUEPRINTS

app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)
