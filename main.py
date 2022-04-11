from flask import Flask, request, url_for, render_template, redirect, flash

app = Flask(__name__)


@app.route('/')
def hello():
    return 'Hello, World!'


# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    # demo creds
    creds = {"username": "test", "password": "password"}

    # getting form data
    username = request.form.get("username")
    password = request.form.get("password")

    # authenticating submitted creds with demo creds
    if username == creds["username"] and password == creds["password"]:
        # inform users if creds are valid
        flash("The credentials provided are valid", "success")
        return redirect(url_for("login"))
    else:
        # inform users if creds are invalid
        flash("You have supplied invalid login credentials!", "danger")
        return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(ssl_context='adhoc')
