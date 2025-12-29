from pathlib import Path

from flask import Blueprint, render_template
from flask_login import login_required
from config import roles_required, User

security_bp = Blueprint('security', __name__, template_folder='templates')

@security_bp.route("/security")
@login_required
@roles_required("sec_admin")
def security():
    users = User.query.all()

    log_file_path = Path("security.log")
    log_entries = []
    if log_file_path.is_file():
        with log_file_path.open("r") as log_file:
            all = log_file.readlines()
            log_entries = [line.strip() for line in all[-10:]]

    return render_template("security/security.html", users=users, log_entries=log_entries)

