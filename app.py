from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from datetime import datetime, timedelta
import os
import hashlib

app = Flask(__name__)
CORS(app)

# Налаштування бази даних
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        print("Підключення до бази даних успішне")
        return conn
    except Exception as e:
        print(f"Помилка підключення до бази даних: {e}")
        return None

def init_db():
    conn = get_db_connection()
    if not conn:
        print("Не вдалося ініціалізувати базу даних: немає підключення")
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
                is_admin BOOLEAN DEFAULT FALSE
            );
        """)
        # Додаємо тестового користувача
        cur.execute("""
            INSERT INTO users (login, password, subscription_end, device_id, session_active, is_admin)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (login) DO NOTHING;
        """, ('proba8', hashlib.sha256('ahegao69'.encode()).hexdigest(), datetime.utcnow() + timedelta(days=365), None, False, False))
        # Додаємо адмін-акаунт
        cur.execute("""
            INSERT INTO users (login, password, subscription_end, device_id, session_active, is_admin)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (login) DO NOTHING;
        """, ('yokoko', hashlib.sha256('admin123'.encode()).hexdigest(), datetime.utcnow() + timedelta(days=365), None, False, True))
        conn.commit()
        print("Таблиця users створена, тестові користувачі додані")
    except Exception as e:
        print(f"Помилка ініціалізації бази даних: {e}")
    finally:
        cur.close()
        conn.close()

init_db()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not login or not password or not confirm_password:
        print(f"Помилка: відсутні необхідні поля - login: {login}")
        return jsonify({"status": "error", "message": "Заповніть усі поля"}), 400
    if password != confirm_password:
        print("Помилка: паролі не співпадають")
        return jsonify({"status": "error", "message": "Паролі не співпадають"}), 400

    conn = get_db_connection()
    if not conn:
        print("Помилка: не вдалося підключитися до бази даних")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute(
            "INSERT INTO users (login, password, subscription_end, session_active, is_admin) VALUES (%s, %s, %s, %s, %s)",
            (login, hashed_password, datetime.utcnow() + timedelta(days=30), False, False)
        )
        conn.commit()
        print(f"Користувач {login} зареєстрований")
        return jsonify({"status": "success", "message": "Реєстрація успішна"})
    except psycopg2.IntegrityError:
        print(f"Помилка: логін {login} уже існує")
        return jsonify({"status": "error", "message": "Логін уже існує"}), 400
    except Exception as e:
        print(f"Помилка реєстрації: {e}")
        return jsonify({"status": "error", "message": f"Помилка сервера: {str(e)}"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    device_id = data.get('device_id')

    if not login or not password or not device_id:
        print(f"Помилка: відсутні необхідні поля - login: {login}, device_id: {device_id}")
        return jsonify({"status": "error", "message": "Відсутні необхідні поля"}), 400

    conn = get_db_connection()
    if not conn:
        print("Помилка: не вдалося підключитися до бази даних")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute("SELECT * FROM users WHERE login = %s AND password = %s", (login, hashed_password))
        user = cur.fetchone()

        if not user:
            print(f"Помилка: користувач з логіном {login} не знайдений або неправильний пароль")
            return jsonify({"status": "error", "message": "Неправильний логін або пароль"}), 401

        subscription_end = user[4]  # subscription_end
        session_active = user[6]    # session_active
        current_time = datetime.utcnow()

        if subscription_end is None or subscription_end < current_time:
            print(f"Помилка: підписка для {login} закінчилася")
            return jsonify({"status": "error", "message": "Підписка закінчилася"}), 403

        if session_active:
            print(f"Помилка: сесія для {login} уже активна")
            return jsonify({"status": "error", "message": "Сесія вже активна на іншому пристрої"}), 403

        cur.execute(
            "UPDATE users SET device_id = %s, session_active = TRUE WHERE login = %s",
            (device_id, login)
        )
        conn.commit()
        print(f"Аутентифікація успішна для {login}")
        return jsonify({"status": "success", "subscription_active": True, "is_admin": user[7]})
    except Exception as e:
        print(f"Помилка аутентифікації: {e}")
        return jsonify({"status": "error", "message": f"Помилка сервера: {str(e)}"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/logout', methods=['POST'])
def logout():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        print(f"Помилка: відсутні необхідні поля для logout - login: {login}")
        return jsonify({"status": "error", "message": "Відсутні необхідні поля"}), 400

    conn = get_db_connection()
    if not conn:
        print("Помилка: не вдалося підключитися до бази даних для logout")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute("SELECT * FROM users WHERE login = %s AND password = %s", (login, hashed_password))
        user = cur.fetchone()

        if not user:
            print(f"Помилка: користувач з логіном {login} не знайдений або неправильний пароль для logout")
            return jsonify({"status": "error", "message": "Неправильний логін або пароль"}), 401

        cur.execute("UPDATE users SET session_active = FALSE WHERE login = %s", (login,))
        conn.commit()
        print(f"Сесія завершена для {login}")
        return jsonify({"status": "success", "message": "Сесія завершена"})
    except Exception as e:
        print(f"Помилка завершення сесії: {e}")
        return jsonify({"status": "error", "message": f"Помилка сервера: {str(e)}"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/profile', methods=['GET'])
def profile():
    login = request.args.get('login')
    if not login:
        print("Помилка: відсутній логін для профілю")
        return jsonify({"status": "error", "message": "Відсутній логін"}), 400

    conn = get_db_connection()
    if not conn:
        print("Помилка: не вдалося підключитися до бази даних для профілю")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT login, created_at, subscription_end, is_admin FROM users WHERE login = %s", (login,))
        user = cur.fetchone()
        if not user:
            print(f"Помилка: користувач {login} не знайдений")
            return jsonify({"status": "error", "message": "Користувач не знайдений"}), 404

        return jsonify({
            "status": "success",
            "login": user[0],
            "created_at": user[1].strftime('%Y-%m-%d %H:%M:%S'),
            "subscription_end": user[2].strftime('%Y-%m-%d %H:%M:%S') if user[2] else None,
            "is_admin": user[3]
        })
    except Exception as e:
        print(f"Помилка профілю: {e}")
        return jsonify({"status": "error", "message": f"Помилка сервера: {str(e)}"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    login = request.args.get('login')
    if not login:
        print("Помилка: відсутній логін для адмін-панелі")
        return jsonify({"status": "error", "message": "Відсутній логін"}), 400

    conn = get_db_connection()
    if not conn:
        print("Помилка: не вдалося підключитися до бази даних для адмін-панелі")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT is_admin FROM users WHERE login = %s", (login,))
        user = cur.fetchone()
        if not user or not user[0]:
            print(f"Помилка: користувач {login} не є адміном")
            return jsonify({"status": "error", "message": "Доступ заборонено"}), 403

        cur.execute("SELECT id, login, created_at, subscription_end FROM users")
        users = cur.fetchall()
        users_data = [
            {"id": u[0], "login": u[1], "created_at": u[2].strftime('%Y-%m-%d %H:%M:%S'), "subscription_end": u[3].strftime('%Y-%m-%d %H:%M:%S') if u[3] else None}
            for u in users
        ]
        print(f"Адмін {login} отримав список користувачів")
        return jsonify({"status": "success", "users": users_data})
    except Exception as e:
        print(f"Помилка адмін-панелі: {e}")
        return jsonify({"status": "error", "message": f"Помилка сервера: {str(e)}"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/admin/subscription', methods=['POST'])
def manage_subscription():
    data = request.get_json()
    admin_login = data.get('admin_login')
    user_login = data.get('user_login')
    action = data.get('action')  # 'activate' or 'deactivate'

    if not admin_login or not user_login or not action:
        print(f"Помилка: відсутні необхідні поля для керування підпискою - admin_login: {admin_login}, user_login: {user_login}, action: {action}")
        return jsonify({"status": "error", "message": "Відсутні необхідні поля"}), 400

    conn = get_db_connection()
    if not conn:
        print("Помилка: не вдалося підключитися до бази даних для керування підпискою")
        return jsonify({"status": "error", "message": "Помилка сервера"}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT is_admin FROM users WHERE login = %s", (admin_login,))
        admin = cur.fetchone()
        if not admin or not admin[0]:
            print(f"Помилка: користувач {admin_login} не є адміном")
            return jsonify({"status": "error", "message": "Доступ заборонено"}), 403

        if action == 'activate':
            cur.execute(
                "UPDATE users SET subscription_end = %s WHERE login = %s",
                (datetime.utcnow() + timedelta(days=30), user_login)
            )
        elif action == 'deactivate':
            cur.execute(
                "UPDATE users SET subscription_end = %s WHERE login = %s",
                (datetime.utcnow() - timedelta(days=1), user_login)
            )
        else:
            print(f"Помилка: невідома дія {action}")
            return jsonify({"status": "error", "message": "Невідома дія"}), 400

        conn.commit()
        print(f"Підписка для {user_login} {'активована' if action == 'activate' else 'деактивована'} адміном {admin_login}")
        return jsonify({"status": "success", "message": f"Підписка {'активована' if action == 'activate' else 'деактивована'}"})
    except Exception as e:
        print(f"Помилка керування підпискою: {e}")
        return jsonify({"status": "error", "message": f"Помилка сервера: {str(e)}"}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
