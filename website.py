import os
import flask
import dotenv
import sqlite3

from flask import render_template, redirect, url_for, request, session
from werkzeug.security import check_password_hash
from datetime import timedelta
from __init__ import *


http = flask.Flask(__name__)
http.secret_key = '3d9efc4wa651728'
http.permanent_session_lifetime = timedelta(days=1)

user_data = {"username": str, "password": str, 
             "email": str, "address": str, "PINcode": int}


# data variables
PORT = int(dotenv.get_key("Database/secrets.env", "PORT"))
HOST = dotenv.get_key("Database/secrets.env", "HOST")
DEBUG = bool(dotenv.get_key("Database/secrets.env", "DEBUG"))

ADMIN_SSID = dotenv.get_key("Database/secrets.env", "ADMIN_SSID")
ADMIN_PSWD = dotenv.get_key("Database/secrets.env", "ADMIN_PSWD")


# database connection
db = sqlite3.connect("Database/mydrugs_database.db")
sql = db.cursor()

sql.execute("""CREATE TABLE IF NOT EXISTS 
            login_dets(username TEXT PRIMARY KEY, password_hash HASH)""")
sql.execute("""CREATE TABLE IF NOT EXISTS 
            user_dets(username TEXT PRIMARY KEY, userID UID, 
            fullname TEXT, email TEXT, address TEXT, PINcode INT)""")
db.commit()

sql.close()
db.close()


# home page redirector route
@http.route("/")
def redirect_to_home():
    return redirect(url_for("home"))

@http.route("/home")
def home():
    return render_template("index.html")


# login page route
@http.route("/login")
def login():
    return render_template("login.html")

@http.route("/login", methods=["POST"]) 
def login_form():

    session["active_user"] = request.form["username"]
    password = request.form["password"]
    user_data = get_user_data(session["active_user"])
    
    if user_data[0] is False:
        return render_template("login.html", error=user_data[-1])

    elif user_data[0] is True:
        if check_password_hash(user_data[-1], str(password)) is True:
            return redirect(url_for("dashboard", user=f'{session["active_user"]}'))

        else: return render_template("login.html", error="Wrong password")


# signup page route
@http.route("/signup")
def signup():
    return render_template("signup.html")

@http.route("/signup", methods=["POST"])
def signup_form():
    global user_data

    username = request.form["username"]
    if user_existstance(username): return render_template("signup.html", error="Username already exists")
    else: user_data["username"] = username

    email = request.form["email"]
    if ('@' and '.com') in email: user_data["email"] = email
    else: return render_template('signup.html', error="Invalid email address")
    
    user_data["fullname"] = request.form["name"]
    user_data["address"] = request.form["address"]
    user_data["PINcode"] = int(request.form["areapin"])

    pswd = request.form["password"]
    if len(pswd) >= 8:
        if pswd == request.form["re-password"]: user_data["password"] = pswd
        else: return render_template('signup.html', error="Password doesn't match")
    else: return render_template('signup.html', error="Password is too short")

    signup_status = register_user(user_data)
    if signup_status is True:
        msg = "Successfully signed-up. Now you can LOGin"
        return render_template("signup.html", success=msg)

    elif signup_status is False:
        msg = "Unable to create your account. Please try after some time."
        return render_template("signup.html", error=msg)

    else:
        msg = "Something unexpected happened in signup route."
        return render_template("signup.html", error=msg)


# logout route
@http.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login", status='logged-out'))


# dashboard page route
@http.route("/dashboard/user:<user>")
def dashboard(user):
    if "active_user" in session:
        return render_template("dashboard.html", username=user)

    else: return redirect(url_for("logout"))


# view profile redirector route
@http.route("/profile/view")
def view_profile_redirect():
    if "active_user" in session:
        return redirect(url_for("view_profile", 
                                username=session["active_user"]))

    else: return redirect(url_for("logout"))

@http.route("/profile/view/user:<username>")
def view_profile(username):
    if "active_user" in session:
            user_data = get_user_data(username, "all")
            return render_template('client_profile_view.html', 
                                username=username, user_data=user_data[-1])

    else: return redirect(url_for("logout"))

@http.route("/profile/view/user:<username>", methods=["POST"])
def edit_profile(username):
    global user_data

    user_data["fullname"] = str(request.form['fullname'])
    user_data["address"] = str(request.form['address'])
    user_data["PINcode"] = int(request.form['areaPIN'])
    user_data["email"] = str(request.form['email'])

    try:
        status = update_user_data(username, user_data)
        if status is True:
            return render_template('client_profile_view.html', 
                                    username=username, 
                                    user_data=user_data, 
                                    update_status="✅")
        elif status is False:
            print("Error updating user info")
            user_data = get_user_data(username, "all")
            return render_template('client_profile_view.html', 
                                username=username, 
                                user_data=user_data, 
                                update_status="❌")

    except Exception as E:
        print("Error updating user info: ", E)
        user_data = get_user_data(username, "all")
        return render_template('client_profile_view.html', 
                            username=username, 
                            user_data=user_data, 
                            update_status="❌")


# executing statement
if __name__ == "__main__":

    http.run(HOST, PORT, DEBUG)