import os
import flask
import dotenv
import sqlite3

from werkzeug.security import generate_password_hash, check_password_hash
from flask import render_template, redirect, url_for, request, session
from __init__ import *


http = flask.Flask(__name__)


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

    username = request.form["username"]
    password = request.form["password"]
    user_data = get_user_data(username)
    
    if user_data[0] is False:
        return render_template("login.html", error=user_data[-1])

    elif user_data[0] is True:
        if check_password_hash(user_data[-1], str(password)) is True:
            return redirect(url_for("dashboard", user=f"@{username}"))

        else: return render_template("login.html", error="Wrong password")


# signup page route
@http.route("/signup")
def signup():
    return render_template("signup.html")

@http.route("/signup", methods=["POST"])
def signup_form():
    pass



# executing statement
if __name__ == "__main__":

    http.run(HOST, PORT, DEBUG)