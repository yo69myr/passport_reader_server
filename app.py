from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    login = data.get("login")
    password = data.get("password")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT login FROM users WHERE login = ?", (login,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "Логін уже зайнятий"})

    password_hash = generate_password_hash(password)
    cursor.execute("INSERT INTO users (login, password_hash, subscription_active, device_id) VALUES (?, ?, ?, ?)",
                   (login, password_hash, False, None))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route("/api/auth", methods=["POST"])
def auth():
    data = request.get_json()
    login = data.get("login")
    password = data.get("password")
    device_id = data.get("device_id")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, subscription_active, device_id FROM users WHERE login = ?", (login,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        if user["subscription_active"]:
            if user["device_id"] is None:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET device_id = ? WHERE login = ?", (device_id, login))
                conn.commit()
                conn.close()
            elif user["device_id"] != device_id:
                return jsonify({"status": "error", "message": "Логін прив’язано до іншого пристрою"})
            return jsonify({"status": "success", "subscription_active": True})
        return jsonify({"status": "error", "message": "Підписка неактивна"})
    return jsonify({"status": "error", "message": "Невірний логін або пароль"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
