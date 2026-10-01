import sqlite3
from flask import request
def f():
    c = sqlite3.connect('x').cursor()
    c.execute(f"SELECT * FROM u WHERE n = '{request.args['n']}'")
