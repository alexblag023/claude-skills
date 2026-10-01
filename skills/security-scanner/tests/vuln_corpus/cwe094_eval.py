from flask import request
def f():
    return eval(request.args['e'])
