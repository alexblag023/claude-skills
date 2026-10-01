from flask import request, make_response
def f():
    return make_response('<h1>' + request.args['n'] + '</h1>')
