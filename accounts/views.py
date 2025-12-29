from urllib import request

from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from accounts.forms import RegistrationForm, LoginForm
from config import User, db, limiter, security_logger
import pyotp
from flask_login import login_user, logout_user, login_required, current_user

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')


@accounts_bp.route("/registration", methods=['GET', 'POST'])
def registration():
    if current_user.is_authenticated:
        flash("You are already logged in!", "info")
        return redirect(url_for("posts.posts"))
    form = RegistrationForm()

    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash("Email already exists", category="danger")
            return render_template("accounts/registration.html", form=form)

        mfa_key = pyotp.random_base32()

        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        mfa_key=mfa_key,
                        mfa_enabled=False)

        db.session.add(new_user)
        db.session.commit()

        new_user.create_log()
        security_logger.info(f"User registered: Email={new_user.email}, Role={new_user.role}, IP={request.remote_addr}")

        new_user_uri = pyotp.totp.TOTP(mfa_key).provisioning_uri(name=form.email.data, issuer_name="CSC2031Blog")

        flash("Account Created, you now need to setup MFA before you can log in", category="success")
        return render_template("accounts/mfa_setup.html", mfa_key=new_user.mfa_key, uri=new_user_uri)

    return render_template("accounts/registration.html", form=form)


@accounts_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def login():
    if current_user.is_authenticated:
        flash("You are already logged in!", "info")
        return redirect(url_for("posts.posts"))

    form = LoginForm()
    max_attempts = 3

    if not session.get("failed_attempts"):
        session["failed_attempts"] = 0
        session["locked"] = False

    if session["locked"]:
        flash("Your account is locked. Please unlock it to try again.", category="danger")
        return render_template("accounts/login.html", form=None)

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:  # If user exists by the given email
            if user.verify_password(form.password.data):
                mfa_pin = pyotp.TOTP(user.mfa_key)
                if mfa_pin.verify(form.mfa_pin.data):
                    session["failed_attempts"] = 0
                    login_user(user)
                    user.mfa_enabled = True
                    db.session.commit()

                    user.update_log(request.remote_addr)
                    security_logger.info(f"User login: Email={user.email}, Role={user.role}, IP={request.remote_addr}")

                    flash("Successfully Logged in", category="success")

                    if user.role == "end_user":
                        return redirect(url_for("posts.posts"))
                    elif user.role =="db_admin":
                        return redirect("https://127.0.0.1:5000/admin")
                    else:
                        return redirect(url_for("security.security"))

                elif not user.mfa_enabled:
                    user_uri = pyotp.totp.TOTP(user.mfa_key).provisioning_uri(name=user.email, issuer_name="CSC2031Blog")
                    flash("You must set up MFA before logging in. Please complete MFA setup.", category="warning")
                    return render_template("accounts/mfa_setup.html", mfa_key=user.mfa_key, uri=user_uri)
                else:
                    flash("Invalid MFA code. Please try again.", category="danger")
                    security_logger.warning(f"Invalid login attempt: Email={form.email.data},"
                                            f" Attempts={session['failed_attempts']}, IP={request.remote_addr}")
                    session["failed_attempts"] += 1
                    if session["failed_attempts"] >= max_attempts:
                        session["locked"] = True
                        security_logger.error(f"Account locked: Email={form.email.data},"
                                              f" Attempts={session['failed_attempts']}, IP={request.remote_addr}")
                        flash("Account has been locked due to too many failed login attempts.", category="danger")

            else:
                session["failed_attempts"] += 1
                if session["failed_attempts"] >= max_attempts:
                    session["locked"] = True
                    security_logger.error(f"Account locked: Email={form.email.data},"
                                          f" Attempts={session['failed_attempts']}, IP={request.remote_addr}")
                    flash("Account has been locked due to too many failed login attempts. Please unlock it to try "
                          "again.",
                          category="danger")
                else:
                    attempts_left = max_attempts - session["failed_attempts"]
                    flash(f"Incorrect password! {attempts_left} attempts left", category="danger")
                    security_logger.warning(f"Invalid login attempt: Email={form.email.data},"
                                            f" Attempts={session['failed_attempts']}, IP={request.remote_addr}")
                    return render_template("accounts/login.html", form=form)
        else:
            flash("Email not found!", category="danger")
            return render_template("accounts/login.html", form=form)

    return render_template("accounts/login.html", form=form)


@accounts_bp.route("/account")
@login_required
def account():
    return render_template("accounts/account.html")

@accounts_bp.route("/unlock_account", methods=["GET"])
def unlock_account():
    session["failed_attempts"] = 0
    session["locked"] = False
    flash("Account has successfully been unlocked.", category="success")
    return redirect(url_for("accounts.login"))

@accounts_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Account has been successfully logged out", category="success")
    return redirect(url_for("accounts.login"))
