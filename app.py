from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)

# Налаштування бази даних із змінної середовища
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Помилка підключення до бази даних: {e}")
        return None

def init_db():
    conn = get_db_connection()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                login VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(100) NOT NULL,
                subscription_end TIMESTAMP,
                device_id VARCHAR(100),
                session_active BOOLEAN DEFAULT FALSE
            );
        """)
        conn.commit()
        print("Таблиця users створена або вже існує")
    except Exception as e:
        print(f"Помилка ініціалізації бази даних: {e}")
    finally:
        cur.close()
        conn.close()

# Ініціалізація бази даних при запуску
init_db()

@app.route('/api/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    device_id = data.get('device_id')

    if not login or not password or not device_id:
        return jsonify({"status": "error", "message": "Відсутні необхідні поля"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE login = %s AND password = %s", (login, password))
        user = cur.fetchone()

        if not user:
            return jsonify({"status": "error", "message": "Неправильний логін або пароль"}), 401

        subscription_end = user[4]  # subscription_end
        session_active = user[5]    # session_active
        current_time = datetime.utcnow()

        if subscription_end is None or subscription_end < current_time:
            return jsonify({"status": "error", "message": "Підписка закінчилася"}), 403

        if session_active:
            return jsonify({"status": "error", "message": "Сесія вже активна на іншому пристрої"}), 403

        cur.execute(
            "UPDATE users SET device_id = %s, session_active = TRUE WHERE login = %s",
            (device_id, login)
        )
        conn.commit()
        return jsonify({"status": "success", "subscription_active": True})
    except Exception as e:
        print(f"Помилка аутентифікації: {e}")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/logout', methods=['POST'])
def logout():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({"status": "error", "message": "Відсутні необхідні поля"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE login = %s AND password = %s", (login, password))
        user = cur.fetchone()

        if not user:
            return jsonify({"status": "error", "message": "Неправильний логін або пароль"}), 401

        cur.execute("UPDATE users SET session_active = FALSE WHERE login = %s", (login,))
        conn.commit()
        return jsonify({"status": "success", "message": "Сесія завершена"})
    except Exception as e:
        print(f"Помилка завершення сесії: {e}")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
