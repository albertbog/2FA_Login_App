from flask import Flask, request, url_for, render_template, redirect, flash
from flask_mysqldb import MySQL
import yaml

app = Flask(__name__)
app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'

#configure SQL server
db = yaml.safe_load(open('db.yaml'))
app.config['MYSQL_HOST']=db['mysql_host']
app.config['MYSQL_USER']=db['mysql_user']
app.config['MYSQL_PASSWORD']=db['mysql_password']
app.config['MYSQL_DB']=db['mysql_db']

mysql = MySQL(app)



# @app.route('/')
# def hello():
#     return 'Hello, World!'


# Route for handling the login page logic
@app.route('/', methods=['GET', 'POST'])
def login():
    # demo creds
   
    creds = {"username": "test", "password": "password"}

    

    if request.method == 'POST':
        # getting form data
        username = request.form.get("username")
        password = request.form.get("password")
        #execute MySQL queries
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name,password) VALUES(%s, %s)", (username,password))
        mysql.connection.commit()
        cur.close()
       

        # authenticating submitted creds with demo creds
        if username == creds["username"] and password == creds["password"]:
            # inform users if creds are valid
            flash("The credentials provided are valid", "success")

            
            return redirect(url_for("login"))
        else:
            # inform users if creds are invalid
            flash("You have supplied invalid login credentials!", "danger")
            
            
            return redirect(url_for("login"))
        
    return render_template("login.html")


@app.route('/users')
def users():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM users")
    if result>0:
        userDetails = cur.fetchall()
        return render_template("users.html", userDetails=userDetails)
    else:
        return render_template("users.html")



if __name__ == "__main__":
 
    app.run(ssl_context='adhoc')
