import os
import json
import random
import string
import dotenv
import hashlib
import sqlite3
import datetime
import smtplib, ssl

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from werkzeug.security import generate_password_hash


ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])


def allowed_file(filename):
    	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def greeting(user=str):
    time = datetime.datetime.now().hour

    if time < 12: return "Good Morning" + ", " + user
    elif time <= 15: return "Good Afternoon" + ", " + user
    else: return "Good Evening" + ", " + user


def create_userID(username: str, id_len: int=6, include_puntuations: bool=False):
    r_file = os.path.join('Database', 'log_file_names.txt')

    with open(r_file, 'r') as log_file:
        available_logs = log_file.readlines()

    for i in available_logs:
        available_logs[available_logs.index(i)] = i[:-1]

    while True:
        if include_puntuations is False:
            uid = ''.join(
                random.choice(string.ascii_letters + string.digits) 
                for _ in range(id_len))

        elif include_puntuations is True:
            uid = ''.join(
                random.choice(string.ascii_letters + string.digits + string.punctuation) 
                for _ in range(id_len))

        uid = username[0] + uid + username[-1]
        uid = hashlib.md5(uid.encode()).hexdigest()

        if uid in available_logs: continue
        else: 
            with open(r_file, 'a') as log_file: log_file.write(f'{uid}\n')
            break

    return uid


def get_user_data(username: str, data: str|None=...):
    db = sqlite3.connect("Database/mydrugs_database.db")
    sql = db.cursor()
    
    try: 
        sql.execute(f"SELECT password_hash FROM login_dets WHERE username=?", (username,))
        password_hash = sql.fetchone()[0]
        
        sql.execute("SELECT * FROM user_dets WHERE username=?", (username,))
        user_data = sql.fetchall()[0]

    except Exception as E: return (False, "Invalid username")

    finally: sql.close(); db.close()

    data_dir = {'pswd_hash': password_hash, 
                'userID': user_data[1], 
                'fullname': user_data[2] ,
                'email': user_data[3], 
                'address': user_data[4], 
                'PINcode': int(user_data[5])}

    if data == "all": return (True, data_dir)
    else: return (True, password_hash)


def read_json(path: str, key: str="key"):
    with open(path, 'r') as jfile:
        jdata = json.load(jfile)

        if key == "key": return jdata
        else: return jdata[key]


def user_existstance(username: str):
    db = sqlite3.connect("Database/mydrugs_database.db")
    sql = db.cursor()

    sql.execute("SELECT username FROM login_dets")
    usernames = sql.fetchall()

    status = False

    if usernames.__len__() > 0:
        for ssid in usernames:
            if ssid[0] == username:
                status = True
            else: pass
    else: status = False

    return status


def register_user(user_data: dict):
    db = sqlite3.connect("Database/mydrugs_database.db")
    sql = db.cursor()

    username = user_data["username"]
    email = user_data["email"]

    fullname = user_data["fullname"]
    address = user_data["address"]
    PINcode = int(user_data["PINcode"])

    userID = create_userID(username)
    password_hash = generate_password_hash(user_data["password"], "sha256")    

    try:
        sql.execute("""INSERT INTO login_dets(username, password_hash) 
                    VALUES(?, ?)""", (username, password_hash))
        sql.execute("""INSERT INTO user_dets(username, userID, fullname, email, address, PINcode) 
                    VALUES(?, ?, ?, ?, ?, ?)""", (username, userID, fullname, email, address, PINcode))
        db.commit()
    except Exception as E: 
        print("Error while registering the user\nError: ", E)
        return False

    sql.close()
    db.close()

    return True


def delete_user_account(username: str):
    user_email = get_user_data(username, "all")[-1]["email"]

    db = sqlite3.connect("Database/mydrugs_database.db")
    sql = db.cursor()

    try:
        sql.execute("DELETE FROM login_dets WHERE username=?", (username,))
        sql.execute("DELETE FROM user_dets WHERE username=?", (username,))

        db.commit()

        sql.close()
        db.close()

        if f'{username}.json' in os.listdir('Database/store/cart'): 
            os.remove(f'Database/store/cart/{username}.json')
        else: pass

        for filename in os.listdir('static/User_profileImages'):
            if username in filename:
                os.remove(f'static/User_profileImages/{filename}')
                break
            else: continue
        
        send_mail(username=username, email=user_email, subject="account-delete")

        return True

    except Exception: return False


def update_user_data(username: str, data: dict):
    db = sqlite3.connect("Database/mydrugs_database.db")
    sql = db.cursor()

    try:
        sql.execute(f"""UPDATE user_dets SET fullname='{str(data["fullname"])}' 
                    WHERE username='{username}'""")
        sql.execute(f"""UPDATE user_dets SET email='{str(data["email"])}' 
                    WHERE username='{username}'""")
        sql.execute(f"""UPDATE user_dets SET address='{str(data["address"])}' 
                    WHERE username='{username}'""")
        sql.execute(f"""UPDATE user_dets SET PINcode={int(data["PINcode"])} 
                    WHERE username='{username}'""")
        db.commit()

        return True

    except Exception as E: print("Error: ", E); return False

    finally: sql.close(); db.close()


def update_cart(username: str, pid: str, method: str, idata=dict):
    file_name = f"Database/store/cart/{username}.json"

    try:
        with open(file_name, 'r') as UCJfile: cart_data = json.load(UCJfile)

        if method == 'add':
            if pid in cart_data.keys():
                cart_data[pid]["product_quantity"] += idata["product_quantity"]
                cart_data[pid]["total_price"] += int(idata["product_quantity"] * idata["product_price"])
            else: cart_data[pid] = idata

        elif method in ['remove', 'pop']: cart_data.pop(pid)

        with open(file_name, 'w') as jfile: json.dump(cart_data, jfile, indent=4)

        return True

    except Exception: return False


def update_login_data(username: str, password: str):
    db = sqlite3.connect("Database/mydrugs_database.db")
    sql = db.cursor()

    try:
        password_hash = generate_password_hash(password, "sha256")
        sql.execute(f"""UPDATE login_dets SET password_hash='{str(password_hash)}'
                    WHERE username='{username}'""")
        db.commit()

        return True

    except Exception as E: print("Error: ", E); return False
    
    finally: sql.close(); db.close()


def generate_2FA_code(code_len: int=6, type: str="int"):
    if type == "int": active_type_content = string.digits
    if type == "str": active_type_content = string.ascii_letters
    if type == "hybrid": active_type_content = string.ascii_letters + string.digits

    code = ''.join(random.choice(active_type_content) 
                   for _ in range(code_len))

    return code


def send_mail(username: str, email: str|None=..., subject: str|None=...):
    date = datetime.datetime.now().strftime('%d-%m-%Y')
    time = datetime.datetime.now().strftime('%I:%M')

    HOST_SSID = dotenv.get_key("Database/secrets.env", "HOST_SSID")
    HOST_PSWD = dotenv.get_key("Database/secrets.env", "HOST_PSWD")

    SMTP_SERVER = dotenv.get_key("Database/secrets.env", "SMTP_SERVER")
    SERVER_PORT = dotenv.get_key("Database/secrets.env", "SERVER_PORT")

    message = MIMEMultipart()

    try: user_email = get_user_data(username, "all")[-1]["email"]
    except Exception: user_email = email

    if subject in ["2FA", "pswd-reset", 'password-reset', None]: 
        code = generate_2FA_code()
        
        message["Subject"] = 'Password Reset Request for MyDrugs Account'
        body = f"""<html>
        <h3>Your 2FA Code for <em><u>Password Reset</u></em> is: </h3>
        <spam><h1 style="background-color: yellow;"><b>{code}</b></h1></spam><br>
        <h3>Password-Reset Request generated on {date} at {time}</h3>
        </html>"""

    elif subject in ["login-2", "forgot-pswd-login", "safe-code", "forgot-password-login"]:
        code = generate_2FA_code(16, "str")
        
        message["Subject"] = 'Login Safe-Code for MyDrugs Account'
        body = f"""<html>
        <h3>Your safe code for <em><u>Loggin-In</u></em> to MyDrugs account is: </h3>
        <spam><h1 style="background-color: yellow;"><b>{code}</b></h1></spam><br>
        <h3>Safe-Code login Request generated on {date} at {time}</h3>
        </html>"""

    elif subject in ['pswd-changed', 'new-pswd', 'password-changed', 'new-password']:
        message["Subject"] = 'Password Changed for MyDrugs Account'
        body = f"""<html>
        <h2>Your password for MyDrugs account has been changed.</h2>
        If it's not you, please contact us immediately.<br>
        <h3>Password changed on {date} at {time}</h3>
        </html>"""

    elif subject in ['register', 'new-user', 'sign-up', 'signup']:
        try: user_fullname = get_user_data(username, "all")[-1]["fullname"]
        except Exception: user_fullname = "User"

        message["Subject"] = 'Welcome to MyDrugs'
        body = f"""<html><h2>{greeting(user_fullname)}</h2><br>
        Thanks for registering with us. We sell premium quality <b>DRUGS</b> at affordable prices.<br>
        Just select the drug you want to buy and add it to your cart. We will deliver it to your doorstep.<br>
        If you have any questions, please contact us through<br>
            ~ <b><a href="mydrugs.allhelp@gmail.com">Mail</a></b> or<br>
            ~ <b><a href="https://api.whatsapp.com/send?phone=8745951248&text=MyDrugs.com">WhatsApp</a></b>

        <br><br>

        Thanks,<br>
        MyDrugs Team
        </html>"""

    elif subject in ['account-delete', 'user-delete', 'user-removed']:
        message["Subject"] = 'Account Deleted for MyDrugs'
        body = f"""<html><h2>{greeting(username)}</h2><br>
        Your account has been deleted from our database.<br>
        Hope you had a great time with us. And Hope you'll join us again soom.<br>

        <h3>Account deleted on {date} at {time}</h3>
        </html>"""

    message["From"] = "MyDrugs.com"
    message["To"] = user_email

    try:
        message.attach(MIMEText(body, "html"))
        
        text = message.as_string()
        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(SMTP_SERVER, int(SERVER_PORT), context=context) as server:
            server.login(HOST_SSID, HOST_PSWD)
            server.sendmail(HOST_SSID, user_email, text)

        return (True, code)

    except Exception as E: 
        print("Error while sending email: ", E)
        return (False, None)
