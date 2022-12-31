import os
import flask
import dotenv
import sqlite3

from flask import render_template, redirect, url_for, jsonify, request, session
from werkzeug.security import check_password_hash
from datetime import timedelta
from __init__ import *


http = flask.Flask(__name__)
http.secret_key = '3d9efc4wa651728'
http.permanent_session_lifetime = timedelta(days=1)

code = ''
safe_code = ''
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
    global safe_code

    session["active_user"] = request.form["username"]
    password = request.form["password"]
    user_data = get_user_data(session["active_user"])
    
    if user_data[0] is False:
        return render_template("login.html", error=user_data[-1])

    elif user_data[0] is True:
        if ((check_password_hash(user_data[-1], str(password)) is True) or (safe_code == password)):
            safe_code = ''
            return redirect(url_for("dashboard", user=f'{session["active_user"]}'))

        else: return render_template("login.html", 
                                     error="Wrong password", 
                                     pswd_invalid=True)


# safe-code sender route
@http.route("/send-safecode")
def send_safecode():
    global safe_code

    mail = send_mail(session["active_user"], 'safe-code')
    if mail[0] is True:
        safe_code = mail[-1]
        return redirect(url_for('login'))

    else: return render_template('login.html', sc_status="Unable to send Safe-Code.")


# password-reset user verification route
@http.route('/password-reset-redirector')
def password_reset_redirector():
    return redirect(url_for("pswd_reset_userVerification"))

@http.route("/password-reset/user-verification")
def pswd_reset_userVerification():
    return render_template('user_verification.html')

@http.route("/password-reset/user-verification", methods=["POST"])
def userVerification_form():
    global code

    session["active_user"] = request.form["username"]
    exist = user_existstance(session["active_user"])
    if exist is True:
        mail = send_mail(session["active_user"], "2FA")
        if mail[0] is True:
            code = mail[-1]
            return redirect(url_for("password_reset", for_user=session["active_user"]))

        elif mail[0] is False:
            return render_template("user_verification.html", status="⚠️ Could not proceed due to technical issue!")
            
    elif exist is False: return render_template('user_verification.html', status="❌ Invalid username!")


# password reset route
@http.route("/password-reset")
def password_reset():
    if "active_user" in session: return render_template('password_reset.html')
    else: return render_template('password_reset.html', validation=False)

@http.route("/password-reset", methods=["POST"])
def password_reset_form():
    global code

    pswd = request.form["new_password"]
    twoFA_code = request.form["2FA"]

    if twoFA_code == code: pass
    else: return render_template('password_reset.html', error="You entered wrong 2FA code!")

    if len(pswd) >= 8:
        if pswd == request.form["confirm_password"]:
            if update_login_data(session["active_user"], pswd) is True:
                session.clear(); code = ''
                return render_template('password_reset.html', success="Now you can ", status="✅")
        else: return render_template('password_reset.html', error="Password doesn't match", status="❌")
    else: return render_template('password_reset.html', error="Password is too short", status="❌")


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
        try: 
            open(f'Database/store/cart/{username}.json', 'x').close()
            with open(f'Database/store/cart/{username}.json', 'w') as ujfile:
                json.dump({}, ujfile, indent=4)

        except Exception as E: pass

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
    try: session.clear()
    except Exception as E: pass
    return redirect(url_for("login", status='logged-out'))


# dashboard page route
@http.route("/dashboard/user:<user>")
def dashboard(user):
    count = 0

    if "active_user" in session:
        data = read_json("Database/store/products.json")
        cart_data = read_json(f'Database/store/cart/{session["active_user"]}.json')
        if cart_data:
            count = cart_data.__len__()

        return render_template("dashboard.html", 
                            username=user, products=data, 
                            item_count=count)

    else: return redirect(url_for("logout"))


# add-to-cart route
@http.route("/cart/add", methods=["POST"])
def add_to_cart():
    if "active_user" in session:
        try:
            pid = request.form["pid"]
            pName = request.form["pname"]
            pImgUrl = request.form["pimg"]
            quantity = int(request.form["quantity"])
            pPrice = int(request.form["pprice"])
            tPrice = quantity * pPrice
            pStatus = request.form["pstatus"]

            user = session["active_user"]

            idata = {"product_name": pName, 
                     "product_img": pImgUrl, 
                     "product_quantity": quantity,
                     "product_price": pPrice,
                     "total_price": tPrice,
                     "product_status": pStatus}

            pdata = read_json(f'Database/store/products.json')

            if (pid, pName, pImgUrl, quantity, pStatus) and (request.method == "POST"):
                if update_cart(user, pid, "add", idata):
                    cart_data = read_json(f'Database/store/cart/{user}.json')
                    if cart_data: count = cart_data.__len__()

                    return render_template('dashboard.html', products=pdata, status=True, item_count=count)
                else: return render_template('dashboard.html', products=pdata, status=False, item_count=count)
            else: pass

        except Exception as E: return render_template('dashboard.html', products=pdata, status=False, item_count=count)

    else: return redirect(url_for("logout"))


# pop-from-cart route
@http.route("/cart/remove", methods=["POST"])
def pop_from_cart():
    if "active_user" in session:
        user = session["active_user"]
        pid = request.form['pid']

        try: 
            if pid and (request.method == "POST"):
                if update_cart(user, pid, 'pop'):
                    cdata = read_json(f'Database/store/cart/{user}.json')
                    return render_template('view_cart.html', username=user, status=True, cart_items=cdata)
                else: return render_template('view_cart.html', username=user, status=False, cart_items=cdata)
            else: pass
        except: return render_template('view_cart.html', username=user, status=False, cart_items=cdata)


# view cart page route
@http.route("/cart/view")
def view_cart():
    if "active_user" in session:
        user = session["active_user"]
        cdata = read_json(f'Database/store/cart/{user}.json')

        try:
            return render_template('view_cart.html', username=user, 
                                   cart_items=cdata)

        except Exception as E:
            print(E)
            return render_template('view_cart.html', username=user, 
                                    error="Unable to load cart items")

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