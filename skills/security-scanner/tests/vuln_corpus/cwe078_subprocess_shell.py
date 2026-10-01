import subprocess
from flask import request
def f():
    subprocess.run('ls ' + request.args['d'], shell=True)
