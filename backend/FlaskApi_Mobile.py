from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import psycopg2
from psycopg2.extras import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)  # Включаем CORS для мобильного приложения
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

# ========== ПОДКЛЮЧЕНИЕ К БД ==========
def get_db_connection():
    try:
        database_url = os.environ.get('DATABASE_URL')
        
        if database_url:
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
            conn = psycopg2.connect(
                dsn=database_url,
                sslmode='require'
            )
            return conn
        else:
            conn = psycopg2.connect(
                host=os.environ.get("DB_HOST", "localhost"),
                user=os.environ.get("DB_USER", "postgres"),
                password=os.environ.get("DB_PASSWORD", ""),
                port=os.environ.get("DB_PORT", "5432"),
                dbname=os.environ.get("DB_NAME", "postgres"),
                client_encoding='utf-8'
            )
            return conn
    except Exception as e:
        print(f"❌ Ошибка подключения к БД: {e}")
        return None

# ========== ДЕКОРАТОРЫ ==========
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Токен отсутствует'}), 401
        
        # В реальном приложении здесь должна быть проверка JWT токена
        # Для упрощения используем session-based подход
        
        return f(*args, **kwargs)
    return decorated

# ========== АУТЕНТИФИКАЦИЯ ==========

@app.route("/api/register", methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', '')

    if not username or not password or not role:
        return jsonify({'error': 'Все поля обязательны'}), 400

    if len(username) < 3:
        return jsonify({'error': 'Имя пользователя минимум 3 символа'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Пароль минимум 6 символов'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Ошибка подключения к БД'}), 500

    try:
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            return jsonify({'error': 'Пользователь уже существует'}), 409

        password_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, password_hash, role)
        )
        conn.commit()
        
        return jsonify({'message': 'Регистрация успешна'}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({'error': f'Ошибка регистрации: {e}'}), 500
    finally:
        cur.close()
        conn.close()

@app.route("/api/login", methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Все поля обязательны'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Ошибка подключения к БД'}), 500

    try:
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            # В реальном приложении здесь нужно генерировать JWT токен
            token = f"simple_token_{user['id']}"
            
            return jsonify({
                'token': token,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role'],
                    'created_at': user['created_at'].isoformat() if user.get('created_at') else None
                }
            }), 200
        else:
            return jsonify({'error': 'Неверные учетные данные'}), 401

    except Exception as e:
        return jsonify({'error': f'Ошибка входа: {e}'}), 500
    finally:
        cur.close()
        conn.close()

# ========== ЗАДАЧИ ==========

@app.route("/api/tasks", methods=['GET'])
def api_get_tasks():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Ошибка подключения к БД'}), 500

    try:
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("""
            SELECT 
                ti.id as task_info_id,
                n.id,
                n.title,
                n.preview as content,
                n.created_at,
                author.username as author_name,
                assigned_by.username as assigned_by_name,
                assigned_to.username as assigned_to_name,
                ti.assigned_to,
                ti.deadline,
                ti.status
            FROM news n
            LEFT JOIN users author ON n.author_id = author.id
            LEFT JOIN task_info ti ON n.id = ti.news_id
            LEFT JOIN users assigned_by ON ti.assigned_by = assigned_by.id
            LEFT JOIN users assigned_to ON ti.assigned_to = assigned_to.id
            ORDER BY n.created_at DESC
        """)
        tasks = cur.fetchall()

        tasks_list = []
        for task in tasks:
            tasks_list.append({
                'id': task['id'],
                'task_info_id': task['task_info_id'],
                'title': task['title'],
                'content': task['content'],
                'created_at': task['created_at'].isoformat() if task['created_at'] else None,
                'author_name': task['author_name'],
                'assigned_by_name': task['assigned_by_name'],
                'assigned_to_name': task['assigned_to_name'],
                'assigned_to': task['assigned_to'],
                'deadline': task['deadline'].isoformat() if task['deadline'] else None,
                'status': task['status'] or 'pending'
            })

        return jsonify(tasks_list), 200

    except Exception as e:
        return jsonify({'error': f'Ошибка загрузки задач: {e}'}), 500
    finally:
        cur.close()
        conn.close()

@app.route("/api/tasks", methods=['POST'])
def api_create_task():
    data = request.get_json()
    title = data.get('title', '').strip()
    content = data.get('task', '').strip()
    assigned_to = data.get('assigned_to')
    deadline = data.get('deadline')
    
    # Для упрощения, используем фиксированный user_id = 1 (team_leader)
    # В реальном приложении нужно извлекать user_id из токена
    user_id = 1

    if not title or not content:
        return jsonify({'error': 'Название и описание обязательны'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Ошибка подключения к БД'}), 500

    try:
        cur = conn.cursor(cursor_factory=DictCursor)
        
        cur.execute(
            "INSERT INTO news (title, preview, author_id) VALUES (%s, %s, %s) RETURNING id",
            (title, content, user_id)
        )
        news_id = cur.fetchone()['id']

        if assigned_to:
            cur.execute(
                "INSERT INTO task_info (news_id, assigned_by, assigned_to, deadline) VALUES (%s, %s, %s, %s)",
                (news_id, user_id, assigned_to, deadline)
            )

        conn.commit()
        return jsonify({'message': 'Задача создана', 'id': news_id}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({'error': f'Ошибка создания задачи: {e}'}), 500
    finally:
        cur.close()
        conn.close()

@app.route("/api/tasks/<int:task_id>/complete", methods=['POST'])
def api_complete_task(task_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Ошибка подключения к БД'}), 500

    try:
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute(
            "UPDATE task_info SET status = 'completed' WHERE id = %s",
            (task_id,)
        )
        conn.commit()

        if cur.rowcount == 0:
            return jsonify({'error': 'Задача не найдена'}), 404

        return jsonify({'message': 'Задача выполнена'}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({'error': f'Ошибка: {e}'}), 500
    finally:
        cur.close()
        conn.close()

@app.route("/api/users/crew", methods=['GET'])
def api_get_crew():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Ошибка подключения к БД'}), 500

    try:
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT id, username, role FROM users WHERE role = 'crew'")
        users = cur.fetchall()

        users_list = [{
            'id': u['id'],
            'username': u['username'],
            'role': u['role']
        } for u in users]

        return jsonify(users_list), 200

    except Exception as e:
        return jsonify({'error': f'Ошибка: {e}'}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
