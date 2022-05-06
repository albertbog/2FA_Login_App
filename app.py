import pyotp
from flask import Flask, render_template, url_for, flash, redirect, request, make_response
from flask_sqlalchemy import SQLAlchemy

from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm
import getpass
from sqlalchemy_utils.functions import database_exists

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
pw = getpass.getpass("Password: ")

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:' + pw + '@localhost'
mysql = SQLAlchemy(app)

path = 'mysql+pymysql://root:' + pw + '@localhost/bemsi_database'
if not database_exists(path):
    mysql.engine.execute("CREATE DATABASE bemsi_database")
    mysql.engine.execute("USE bemsi_database")
    mysql.engine.execute(
        "CREATE TABLE users(email varchar(120), username varchar(20), password_hash varchar(200), otp_secret varchar(200), sec_factor_cookie varchar(200))")
else:
    mysql.engine.execute("USE bemsi_database")
migrate = Migrate(app, mysql)

posts = [
    {
        'author': 'Jakub Kowalczyk',
        'title': 'Pierwsza pała',
        'content': 'Zapodał Jerzy Pofa',
        'date_posted': '20 Grudnia, 2021'
    },
    {
        'author': 'Jerzy Pofa',
        'title': 'Należało się',
        'content': 'Wysłano z Samsung smart fridge',
        'date_posted': '21 Grudnia, 2021'
    }
]


@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', posts=posts)


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()

        if user is None:
            secret = pyotp.random_base32()
            user = Users(username=form.username.data, email=form.email.data, password=form.password.data,
                         otp_secret=secret, sec_factor_cookie="")
            form.username.data = ''
            form.password.data = ''
            form.confirm_password.data = ''
            form.email.data = ''

            flash(f'Account created!', 'success')

            mysql.session.add(user)
            mysql.session.commit()
        else:
            flash(f'Error (maybe this account already exists)!', 'danger')

    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                flash('Please enter code from second factor', 'success')
                res = redirect(url_for("login_2fa_form"))

                cookie_value = pyotp.random_base32()
                user.sec_factor_cookie = cookie_value
                mysql.session.commit()
                res.set_cookie('token', value=cookie_value, secure=True)
                return res
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html', title='Login', form=form)


@app.route('/users')
def users():
    result = mysql.engine.execute("SELECT * FROM users")
    return render_template("users.html", userDetails=result)


# 2FA page route
@app.route("/login/2fa/")
def generate_secret_2fa():
    form = LoginForm()

    secret = pyotp.random_base32()
    return render_template("login_2fa.html", secret=secret, form=form)


# 2FA form route
@app.route("/login/2fa/", methods=["POST"])
def login_2fa_form():
    # getting secret key used by user
    cookie = request.cookies.get('token')
    user = Users.query.filter_by(sec_factor_cookie=cookie).first()
    secret = user.otp_secret
    # getting OTP provided by user
    otp = int(request.form.get("otp"))

    # verifying submitted OTP with PyOTP
    if pyotp.TOTP(secret).verify(otp):
        # inform users if OTP is valid
        flash("The TOTP 2FA token is valid", "success")
        return redirect(url_for("home"))
    else:
        # inform users if OTP is invalid
        flash("You have supplied an invalid 2FA token!", "danger")
        return redirect(url_for("home"))


class Users(mysql.Model):
    email = mysql.Column(mysql.String(120), nullable=False, unique=True, primary_key=True)
    username = mysql.Column(mysql.String(20), nullable=False, unique=True)
    password_hash = mysql.Column(mysql.String(200), nullable=False)
    otp_secret = mysql.Column(mysql.String(200), nullable=False)
    sec_factor_cookie = mysql.Column(mysql.String(200), nullable=False)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute!')

    @password.setter
    def password(self, pw):
        self.password_hash = generate_password_hash(pw, "sha256")

    @property
    def mail(self):
        raise AttributeError('email is not a readable attribute!')

    @mail.setter
    def mail(self, pw):
        self.email = pw + '1'


if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'))
