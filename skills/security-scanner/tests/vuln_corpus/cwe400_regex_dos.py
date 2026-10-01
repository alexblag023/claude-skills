import re
from flask import request
def f():
    return re.match(request.args['p'], 'aaaa')
