from config import app
from flask import render_template, request, redirect, url_for
import re


@app.route("/")
def index():
    return render_template("home/index.html")


# Rate limit reached error detection
@app.errorhandler(429)
def rate_limit_exceeded(e):
    return render_template(
        "errors/error.html",
        error_title="Rate limit exceeded",
        error_message="You have exceeded the maximum number of allowed requests, please try again later!"
    )


# Bad Request error detection
@app.errorhandler(400)
def bad_request(e):
    return render_template('errors/error.html', error_title="Bad Request",
                           error_message="the server could not process the request due to something the server "
                                         "considered to be a client error!"), 400


# Not Found error detection
@app.errorhandler(404)
def not_found(e):
    return render_template('errors/error.html', error_title="Not Found",
                           error_message="the server could not find the requested resource!"), 404


# Internal Server Error error detection
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/error.html', error_title="Internal Server Error",
                           error_message="the server encountered an unexpected condition that prevented it from "
                                         "fulfilling the request"), 500


# Not Implemented error detection
@app.errorhandler(501)
def not_implemented(e):
    return render_template('errors/error.html', error_title="Not Implemented",
                           error_message="the server does not support the functionality required to fulfill the request"), 501


@app.before_request
def detect_attack():  # Detects SQL injection, XSS, Path traversal attacks and redirects to error page if found
    attack_conditions = {
        "SQL Injection": [
            r"union", r"select", r"insert", r"drop", r"alter", r";", r"`", r"'"
        ],
        "XSS": [
            r"<script>", r"<iframe>", r"%3Cscript%3E", r"%3Ciframe%3E"
        ],
        "Path Traversal": [
            r"\.\./", r"\.\.", r"%2e%2e%2f", r"%2e%2e/", r"\.\. %2f"
        ]
    }

    for attack_type, attack_patterns in attack_conditions.items():
        for pattern in attack_patterns:
            if re.search(pattern, request.path, re.IGNORECASE) or re.search(pattern, request.query_string.decode(),
                                                                            re.IGNORECASE):
                return render_template("errors/error.html", error_title="Attack Detected",
                                       error_message=f"Warning: {attack_type} attack attempt detected!")
    return None


if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))
