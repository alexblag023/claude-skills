import requests
from flask import request
def f():
    return requests.get(request.args['url']).text
