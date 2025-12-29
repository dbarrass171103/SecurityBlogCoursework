from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, regexp, Email
from flask_wtf import RecaptchaField


class RegistrationForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email(message="Invalid Email!")])
    firstname = StringField(validators=[DataRequired(), regexp(r"^[A-Za-z\-]+$",
                                                               message="Firstname must contain only letters or hyphens.")])
    lastname = StringField(validators=[DataRequired(), regexp(r"^[A-Za-z\-]+$",
                                                              message="Lastname must contain only letters or hyphens.")])
    phone = StringField(validators=[DataRequired(), regexp(r"^(02\d-\d{8}|011\d-\d{7}|01\d1-\d{7}|01\d{3}-\d{5,6})$",
                                                           message="Please enter a valid UK landline phone number, "
                                                                   "including hyphen.")])
    password = PasswordField(validators=[DataRequired()])
    confirm_password = PasswordField(validators=[DataRequired(),
                                                 EqualTo("password", message="Both password fields must be equal!"),
                                                 Length(min=8, max=15,
                                                        message="Password must be between 8 and 15 characters long!"),
                                                 regexp(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^\w]).+$",
                                                        message="Password requires 1 uppercase character, 1 lowercase "
                                                                "character,"
                                                                " 1 digit and 1 special characters")])
    submit = SubmitField()


class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    mfa_pin = StringField(validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField()
