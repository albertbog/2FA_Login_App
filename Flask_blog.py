from flask import Flask, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy

from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm
import getpass
from sqlalchemy_utils.functions import database_exists





app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
pw = 'Password123' #getpass.getpass("Password: ")

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:'+ pw +'@localhost'
mysql = SQLAlchemy(app)

path = 'mysql+pymysql://root:'+ pw +'@localhost/bemsi_database'
if not database_exists(path):
     mysql.engine.execute("CREATE DATABASE bemsi_database")
     mysql.engine.execute("USE bemsi_database")
     mysql.engine.execute("CREATE TABLE users(email varchar(40), username varchar(20), password varchar(40))")
else:
    mysql.engine.execute("USE bemsi_database")   
migrate = Migrate(app,mysql)


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
        
            hashed_pass = generate_password_hash(form.password.data, "sha256")
            user = Users(username = form.username.data, email = form.email.data, password = form.password.data)
            mysql.session.add(user)
            mysql.session.commit()
            #OR
            # cur = mysql.connection.cursor()
            # cur.execute("INSERT INTO users(name,password) VALUES(%s, %s)", (username,password))
            # mysql.connection.commit()
            # cur.close()
            
            form.username.data = ''
            form.password.data = ''
            form.confirm_password.data = ''
            form.email.data = ''

            flash(f'Account created!', 'success')
            return redirect(url_for('home'))
    flash('Registration unsuccessful')
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.email.data == 'jerzy@pofa.com' and form.password.data == '12lat':
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)




@app.route('/users')
def users():

    result = mysql.engine.execute("SELECT * FROM users")
    return render_template("users.html", userDetails=result)

   



class Users(mysql.Model):
    email = mysql.Column(mysql.String(120), nullable=False, unique=True, primary_key = True)
    username = mysql.Column(mysql.String(20), nullable=False, unique=True)
    password = mysql.Column(mysql.String(128),nullable=False)


    # @property
    # def password(self):
    #     raise AttributeError('password is not a readable attribute!')

    # # @password.setter
    # # def password(self, pw):
    # #     self.password = generate_password_hash(pw)

    # def verify_password(self, password):
    #     return check_password_hash(self.password, password)



if __name__ == '__main__':

    app.run(debug=True)




