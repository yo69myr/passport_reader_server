from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

def get_db():
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            login TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            subscription_active BOOLEAN NOT NULL,
            device_id TEXT,
            session_active BOOLEAN DEFAULT FALSE,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    login = data.get("login")
    password = data.get("password")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT login FROM users WHERE login = %s", (login,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "Логін уже зайнятий"})

    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO users (login, password, subscription_active, device_id, session_active, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
        (login, password, False, None, False, created_at)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    login = data.get("login")
    password = data.get("password")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT login, password, subscription_active, created_at, session_active FROM users WHERE login = %s", (login,))
    user = cursor.fetchone()
    conn.close()

    if user and user[1] == password:
        if user[4]:  # session_active
            return jsonify({"status": "error", "message": "Сесія вже активна для цього користувача"})
        is_admin = login == "yokoko" and password == "anonanonNbHq1554o"
        return jsonify({
            "status": "success",
            "login": user[0],
            "subscription_active": user[2],
            "created_at": user[3],
            "is_admin": is_admin
        })
    return jsonify({"status": "error", "message": "Невірний логін або пароль"})

@app.route("/api/auth", methods=["POST"])
def auth():
    data = request.get_json()
    login = data.get("login")
    password = data.get("password")
    device_id = data.get("device_id")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password, subscription_active, device_id, session_active FROM users WHERE login = %s", (login,))
    user = cursor.fetchone()

    if user and user[0] == password:
        if user[3]:  # session_active
            conn.close()
            return jsonify({"status": "error", "message": "Сесія вже активна для цього користувача"})
        if user[1]:  # subscription_active
            if user[2] is None:
                cursor.execute("UPDATE users SET device_id = %s, session_active = TRUE WHERE login = %s", (device_id, login))
            elif user[2] != device_id:
                conn.close()
                return jsonify({"status": "error", "message": "Логін прив’язано до іншого пристрою"})
            else:
                cursor.execute("UPDATE users SET session_active = TRUE WHERE login = %s", (login,))
            conn.commit()
            conn.close()
            return jsonify({"status": "success", "subscription_active": True})
        conn.close()
        return jsonify({"status": "error", "message": "Підписка неактивна"})
    conn.close()
    return jsonify({"status": "error", "message": "Невірний логін або пароль"})

@app.route("/api/logout", methods=["POST"])
def logout():
    data = request.get_json()
    login = data.get("login")
    password = data.get("password")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE login = %s", (login,))
    user = cursor.fetchone()

    if user and user[0] == password:
        cursor.execute("UPDATE users SET session_active = FALSE WHERE login = %s", (login,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    conn.close()
    return jsonify({"status": "error", "message": "Невірний логін або пароль"})

@app.route("/api/admin/users", methods=["POST"])
def get_users():
    data = request.get_json()
    login = data.get("login")
    password = data.get("password")
    if login != "yokoko" or password != "anonanonNbHq1554o":
        return jsonify({"status": "error", "message": "Невірні адмін-дані"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT login, password, subscription_active, created_at, session_active FROM users")
    users = [{"login": row[0], "password": row[1], "subscription_active": row[2], "created_at": row[3], "session_active": row[4]} for row in cursor.fetchall()]
    conn.close()
    return jsonify({"status": "success", "users": users})

@app.route("/api/admin/update_subscription", methods=["POST"])
def update_subscription():
    data = request.get_json()
    login = data.get("login")
    password = data.get("password")
    if login != "yokoko" or password != "anonanonNbHq1554o":
        return jsonify({"status": "error", "message": "Невірні адмін-дані"}), 401

    user_login = data.get("user_login")
    subscription_active = data.get("subscription_active")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET subscription_active = %s WHERE login = %s", (subscription_active, user_login))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
