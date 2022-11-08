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
http.permanent_session_lifetime = timedelta(minutes=1)

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
            user_dets(username TEXT PRIMARY KEY, userID UID, email TEXT, address TEXT, PINcode INT)""")
db.commit()

sql.close()
db.close()


# home page redirector route
@http.route("/")
def redirect_to_home():
    return redirect(url_for("home"))


# Home/index page route
@http.route("/home")
def home():
    return render_template("index.html")


# login page route
@http.route("/signin")
def signin():
    return render_template("login.html")

@http.route("/signin", methods=["POST"]) 
def signin_form():

    session["active_user"] = request.form["username"]
    password = request.form["password"]
    user_data = get_user_data(session["active_user"])
    
    if user_data[0] is False:
        return render_template("login.html", error=user_data[-1])

    elif user_data[0] is True:
        if check_password_hash(user_data[-1], str(password)) is True:
            return redirect(url_for("dashboard", user=f'@{session["active_user"]}'))

        else: return render_template("login.html", error="Wrong password")


# signup page route
@http.route("/signup")
def signup_page1():
    return render_template("signup.html")

@http.route("/signup", methods=["POST"])
def signup_form1():
    global user_data

    user_data["fullname"] = request.form["fullname"]
    user_data["username"] = request.form["username"]
    user_data["email"] = request.form["email"]

    user_data["address"] = request.form["address"]
    user_data["PINcode"] = request.form["PINcode"]

    signup_status = put_user_data(user_data)
    if signup_status is True:
        msg = "Successfully signed-up. Now you can LOGin"
        return render_template("signup.html", status=msg)

    elif signup_status is False:
        msg = "Unable to create your account. Please try after some time."
        return render_template("signup.html", status=msg)

    else:
        msg = "Something unexpected happened in signup route."
        return render_template("signup.html", status=msg)


# logout route
@http.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("signin", status='logged-out'))



# executing statement
if __name__ == "__main__":

    http.run(HOST, PORT, DEBUG)