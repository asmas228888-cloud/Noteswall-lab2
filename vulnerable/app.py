"""
Лабораторная работа №2 — уязвимое веб-приложение "NotesWall".

Простое приложение заметок:
- регистрация и вход пользователей;
- после входа пользователь видит общую "стену заметок" (все заметки всех
  пользователей на одной странице — это сделано специально, чтобы было
  удобно демонстрировать Stored XSS: одна заметка показывается всем);
- пользователь может добавить свою заметку.

В файле НАМЕРЕННО заложены две уязвимости:

1. SQL Injection (OWASP Top 10 2021 — A03:2021 Injection) — в маршруте
   /login. Запрос на проверку логина/пароля собирается конкатенацией строк.

2. Stored XSS (OWASP Top 10 2021 — A03:2021 Injection) — в маршруте
   /notes. Содержимое заметки выводится в шаблон с фильтром `| safe`,
   из-за чего HTML/JS, введённый пользователем, не экранируется и
   выполняется в браузере любого, кто откроет стену заметок.

Для простоты лабораторной работы пароли в этой версии хранятся в БД в
открытом виде (это отдельная плохая практика — OWASP A02:2021
Cryptographic Failures — она НЕ входит в число двух разбираемых в этой
работе уязвимостей и в части 3 не исправляется, см. заключение).
"""

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
        # УЯЗВИМОСТЬ №1: SQL Injection (OWASP A03:2021 — Injection)
        #
        # Запрос собирается конкатенацией/f-строкой из пользовательского
        # ввода вместо параметризованного запроса. Злоумышленник может
        # изменить структуру SQL-запроса, подставив спецсимволы ' и --.
        # -------------------------------------------------------------
        query = (
            "SELECT id, username, is_admin FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        app.logger.info("LOGIN SQL: %s", query)
        try:
            cur = db.execute(query)
            user = cur.fetchone()
        except sqlite3.OperationalError as exc:
            # Синтаксическая ошибка SQL "протекает" в ответ — это тоже
            # характерная черта уязвимых к SQLi приложений (error-based
            # разведка).
            return f"Database error: {exc}", 500

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
