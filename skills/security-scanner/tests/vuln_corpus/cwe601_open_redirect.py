from flask import request, redirect
def f():
    return redirect(request.args['next'])
