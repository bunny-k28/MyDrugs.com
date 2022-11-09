import os
import random
import string
import sqlite3

from werkzeug.security import generate_password_hash


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


def put_user_data(user_data: dict):
    db = sqlite3.connect("Database/mydrugs_database.db")
    sql = db.cursor()

    username = user_data["username"]
    password_hash = generate_password_hash(user_data["password"], "sha256")

    userID = create_userID(username)
    email = user_data["email"]
    address = user_data["address"]
    PINcode = int(user_data["PINcode"])

    try:
        sql.execute("""INSERT INTO login_dets(username, password_hash) 
                    VALUES(?, ?)""", (username, password_hash))
        db.commit()
    except Exception as E: 
        print("Error while registering the user\nError: ", E)
        return False

    try:
        sql.execute("""INSERT INTO user_dets(username, userID, email, address, PINcode) 
                    VALUES(?, ?, ?, ?, ?)""", (username, userID, email, address, PINcode))
    except Exception as E: 
        print("Error while registering the user\nError: ", E)
        return False

    sql.close()
    db.close()

    return True
