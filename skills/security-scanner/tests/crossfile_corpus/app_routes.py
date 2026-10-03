# Межфайловый taint: источник здесь, sink — в db_helper.py (другой модуль).
# Semgrep OSS делает taint только ВНУТРИ одного метода/файла и эту цепочку НЕ видит.
# CodeQL (межпроцедурный CPG) связывает source->sink через вызов между файлами.
from flask import Flask, request
from db_helper import lookup_user

app = Flask(__name__)

@app.route('/user')
def user():
    uid = request.args['id']          # SOURCE: внешний ввод
    return lookup_user(uid)           # ввод уходит в helper из другого файла
