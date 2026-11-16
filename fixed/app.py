import sqlite3
from flask import Flask, g, request, redirect, url_for, session, render_template

app = Flask(__name__)
app.secret_key = "lab2-insecure-demo-secret-key"  # только для учебного стенда
DATABASE = "notes.db"


# ---------------------------------------------------------------------------
# Работа с базой данных
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Создаёт таблицы и тестовых пользователей, если БД ещё не создана."""
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    cur = db.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            ("admin", "SuperSecretAdminPass1", 1),
        )
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            ("alice", "alice123", 0),
        )
        db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Маршруты
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("notes"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
                (username, password),
            )
            db.commit()
        except sqlite3.IntegrityError:
            error = "Пользователь с таким именем уже существует."
        else:
            return redirect(url_for("login"))
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()

        # -------------------------------------------------------------
        # ИСПРАВЛЕНИЕ УЯЗВИМОСТИ №1: SQL Injection
        #
        # Вместо конкатенации строк используется параметризованный
        # запрос с плейсхолдерами "?". Библиотека sqlite3 сама
        # экранирует значения и передаёт их отдельно от текста запроса,
        # поэтому ввод вида "admin' --" воспринимается СУГУБО как
        # значение строки, а не как часть SQL-синтаксиса.
        # -------------------------------------------------------------
        query = "SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?"
        cur = db.execute(query, (username, password))
        user = cur.fetchone()

        if user is not None:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            return redirect(url_for("notes"))
        error = "Неверное имя пользователя или пароль."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/notes", methods=["GET", "POST"])
def notes():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        # Заголовок и содержимое сохраняются как есть, без какой-либо
        # санитизации — это само по себе ещё не уязвимость (её вносит
        # способ последующего вывода в шаблоне, см. notes.html).
        db.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (session["user_id"], title, content),
        )
        db.commit()
        return redirect(url_for("notes"))

    rows = db.execute(
        "SELECT notes.id, notes.title, notes.content, users.username "
        "FROM notes JOIN users ON notes.user_id = users.id "
        "ORDER BY notes.id DESC"
    ).fetchall()
    return render_template("notes.html", notes=rows, username=session["username"])


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
