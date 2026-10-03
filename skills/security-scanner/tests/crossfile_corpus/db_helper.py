import sqlite3

def lookup_user(uid):
    conn = sqlite3.connect('app.db')
    cur = conn.cursor()
    # SINK: конкатенация в SQL. Источник (request.args) пришёл из app_routes.py.
    cur.execute("SELECT * FROM users WHERE id = " + uid)   # CWE-89 cross-file
    return cur.fetchall()
