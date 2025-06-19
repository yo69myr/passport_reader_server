from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from datetime import datetime, timedelta
import os
import hashlib

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Налаштування бази даних
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                subscription_end TIMESTAMP,
                device_id VARCHAR(100),
                session_active BOOLEAN DEFAULT FALSE,
                is_admin BOOLEAN DEFAULT FALSE,
                subscription_active BOOLEAN DEFAULT FALSE
            );
        """)
        # Створення адміна, якщо його немає
        admin_login = os.environ.get('ADMIN_LOGIN', 'admin')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        hashed_password = hashlib.sha256(admin_password.encode()).hexdigest()
        
        cur.execute("SELECT * FROM users WHERE login = %s", (admin_login,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (login, password, is_admin, subscription_active) VALUES (%s, %s, %s, %s)",
                (admin_login, hashed_password, True, True)
            )
            conn.commit()
            print("Адміністратора створено")
        
        conn.commit()
        print("Таблиця users готова")
    except Exception as e:
        print(f"Помилка ініціалізації бази даних: {e}")
    finally:
        cur.close()
        conn.close()

init_db()

@app.route('/api/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    device_id = data.get('device_id')

    if not all([login, password, device_id]):
        return jsonify({"status": "error", "message": "Відсутні необхідні поля"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute("SELECT * FROM users WHERE login = %s AND password = %s", (login, hashed_password))
        user = cur.fetchone()

        if not user:
            return jsonify({"status": "error", "message": "Неправильний логін або пароль"}), 401

        user_data = {
            "id": user[0],
            "login": user[1],
            "subscription_end": user[4],
            "device_id": user[5],
            "session_active": user[6],
            "is_admin": user[7],
            "subscription_active": user[8]
        }

        current_time = datetime.utcnow()
        if user_data["subscription_end"] and isinstance(user_data["subscription_end"], datetime):
            if user_data["subscription_end"] < current_time:
                return jsonify({"status": "error", "message": "Підписка закінчилася"}), 403

        if user_data["session_active"]:
            return jsonify({"status": "error", "message": "Сесія вже активна на іншому пристрої"}), 403

        cur.execute(
            "UPDATE users SET device_id = %s, session_active = TRUE WHERE login = %s",
            (device_id, login)
        )
        conn.commit()
        return jsonify({
            "status": "success",
            "subscription_active": True,
            "is_admin": user_data["is_admin"]
        })
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

    if not all([login, password]):
        return jsonify({"status": "error", "message": "Відсутні необхідні поля"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute("SELECT * FROM users WHERE login = %s AND password = %s", (login, hashed_password))
        if not cur.fetchone():
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

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    if not all([login, password]):
        return jsonify({"status": "error", "message": "Відсутні необхідні поля"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Перевірка, чи існує користувач
        cur.execute("SELECT * FROM users WHERE login = %s", (login,))
        if cur.fetchone():
            return jsonify({"status": "error", "message": "Користувач з таким логіном вже існує"}), 400

        # Створення нового користувача
        subscription_end = datetime.utcnow() + timedelta(days=30)  # 30-денна пробна підписка
        cur.execute(
            "INSERT INTO users (login, password, subscription_end, subscription_active) VALUES (%s, %s, %s, %s)",
            (login, hashed_password, subscription_end, True)
        )
        conn.commit()
        return jsonify({"status": "success", "message": "Акаунт успішно створено"})
    except Exception as e:
        print(f"Помилка реєстрації: {e}")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    if not all([login, password]):
        return jsonify({"status": "error", "message": "Відсутні необхідні поля"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute("SELECT * FROM users WHERE login = %s AND password = %s", (login, hashed_password))
        user = cur.fetchone()

        if not user:
            return jsonify({"status": "error", "message": "Неправильний логін або пароль"}), 401

        user_data = {
            "status": "success",
            "login": user[1],
            "created_at": user[3].strftime("%Y-%m-%d %H:%M:%S") if user[3] else "",
            "subscription_active": user[8],
            "is_admin": user[7]
        }
        return jsonify(user_data)
    except Exception as e:
        print(f"Помилка входу: {e}")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
