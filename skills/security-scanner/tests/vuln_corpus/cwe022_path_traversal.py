from flask import request
def f():
    return open('/data/' + request.args['f']).read()
