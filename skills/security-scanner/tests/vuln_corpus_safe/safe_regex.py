import re
from flask import request
def f():
    return re.match(re.escape(request.args['p']), 'aaaa')
