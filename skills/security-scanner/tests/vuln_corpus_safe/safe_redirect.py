from flask import redirect, url_for
def f():
    return redirect(url_for('index'))
