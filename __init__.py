import sqlite3


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
                'email': user_data[2], 
                'address': user_data[3], 
                'PINcode': int(user_data[4])}

    if type(data) is str: return (True, data_dir)
    else: return (True, password_hash)


def put_user_data(user_data: dict):
    pass