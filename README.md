# NotesWall — лабораторная работа по веб-безопасности (SQL Injection + Stored XSS)

Учебный проект: простое Flask-приложение заметок с **намеренно внедрёнными**
уязвимостями из OWASP Top 10, скрипты для их эксплуатации через HTTP и
патчи с исправлениями.


## Что внутри

| Папка | Содержимое |
|---|---|
| `vulnerable/` | Исходная уязвимая версия приложения |
| `fixed/` | Та же функциональность, обе уязвимости исправлены |
| `exploits/` | Python-скрипты, эксплуатирующие уязвимости через HTTP (`requests`) |
| `patches/` | Патчи в формате unified diff, превращающие `vulnerable` в `fixed` |

## Уязвимости

1. **SQL Injection** (OWASP A03:2021 — Injection) — в `/login`. Запрос к
   БД собирается конкатенацией строк, что позволяет войти под любым
   пользователем без знания пароля (`username = admin' --`).
2. **Stored XSS** (OWASP A03:2021 — Injection) — в `/notes`. Содержимое
   заметки выводится с фильтром Jinja2 `| safe`, из-за чего
   `<script>`-код, введённый одним пользователем, выполняется в
   браузере любого, кто откроет общую стену заметок.

Подробный разбор принципа каждой уязвимости, HTTP-запросы и объяснение
исправлений — в отчёте по лабораторной работе (прилагается отдельно).

## Требования

- Python 3.9+
- Flask 3.1.3 (см. `vulnerable/requirements.txt` и `fixed/requirements.txt`)
- `requests` для скриптов-эксплойтов

## Установка

```bash
python -m venv venv
# Windows:
venv\Scripts\activate.bat
# macOS/Linux:
source venv/bin/activate

cd vulnerable
pip install -r requirements.txt
pip install requests
cd ..
```

## Запуск уязвимой версии

```bash
cd vulnerable
python app.py
```

Приложение поднимется на `http://127.0.0.1:5000`. При первом запуске
автоматически создаётся `notes.db` с тестовыми пользователями:

| Логин | Пароль |
|---|---|
| `admin` | `SuperSecretAdminPass1` |
| `alice` | `alice123` |

## Запуск эксплойтов (в отдельном терминале, сервер должен работать)

```bash
cd exploits
python exploit_sqli.py   # обход аутентификации через SQL-инъекцию
python exploit_xss.py    # внедрение <script> в общую стену заметок
```

## Запуск исправленной версии

```bash
cd fixed
python app.py
```

Те же скрипты из `exploits/`, запущенные без изменений против этой
версии, больше не срабатывают.

## Применение патчей

Патчи превращают чистую копию `vulnerable/` в `fixed/`:

```bash
cp -r vulnerable patch_demo   # Windows: xcopy vulnerable patch_demo /E /I
cd patch_demo
patch -p1 < ../patches/sqli_fix.patch
patch -p1 < ../patches/xss_fix.patch
```

На Windows команда `patch` доступна через **Git Bash** (входит в состав
[Git for Windows](https://git-scm.com/download/win)).

## Структура файлов

```
.
├── vulnerable/
│   ├── app.py
│   ├── requirements.txt
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── register.html
│       └── notes.html
├── fixed/
│   ├── app.py
│   ├── requirements.txt
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── register.html
│       └── notes.html
├── exploits/
│   ├── exploit_sqli.py
│   └── exploit_xss.py
├── patches/
│   ├── sqli_fix.patch
│   └── xss_fix.patch
└── README.md
```

### SQL Injection — маршрут `/login`

В `vulnerable/app.py` запрос к базе собирается конкатенацией строки
(f-строкой) прямо из полей формы — логина и пароля. SQL-движок не
отличает «текст запроса, написанный разработчиком» от «данные,
введённые пользователем»: он просто выполняет итоговую строку целиком.
Поэтому спецсимволы вроде кавычки `'` и двойного тире `--` (начало
комментария в SQL) позволяют злоумышленнику дописать в запрос свою
логику — в данном случае обрезать условие на пароль и войти под любым
существующим логином без пароля:

```python
query = (
    "SELECT id, username, is_admin FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
cur = db.execute(query)
user = cur.fetchone()
```

В `fixed/app.py` то же самое место переписано на параметризованный
запрос: текст SQL с плейсхолдерами `?` передаётся в `execute()`
отдельно от значений. Драйвер `sqlite3` подставляет `username` и
`password` уже как данные, а не как часть SQL-кода, поэтому кавычки и
`--` в них больше не имеют особого значения:

```python
query = "SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?"
cur = db.execute(query, (username, password))
user = cur.fetchone()
```

### Stored XSS — стена заметок (`/notes`)

В `vulnerable/templates/notes.html` содержимое заметки выводится через
фильтр Jinja2 `| safe`, который отключает стандартное автоэкранирование
шаблонизатора. В результате HTML/JS, который ввёл автор заметки,
попадает в страницу «как есть» и выполняется в браузере любого, кто
откроет стену заметок — а не только у того, кто эту заметку написал:

```html
<p>{{ note.content | safe }}</p>
```

В `fixed/templates/notes.html` фильтр `| safe` просто убран. Jinja2 по
умолчанию экранирует спецсимволы (`<`, `>`, `"`, `'`), поэтому текст
вроде `<script>...</script>` превращается в видимый, но безобидный
текст, а не в исполняемый код:

```html
<p>{{ note.content }}</p>
```

### Почему пароли хранятся в открытом виде

Это намеренное упрощение ради наглядности классического сценария
SQL-инъекции в форме логина. Это отдельная проблема (OWASP A02:2021 —
Cryptographic Failures), которая **не входит** в число двух
анализируемых в этой работе уязвимостей, поэтому в `fixed/` она не
исправлена — подробнее см. раздел «Заключение» отчёта по лабораторной
работе.
