import os
from flask import request
def f():
    os.system('ping ' + request.args['h'])
