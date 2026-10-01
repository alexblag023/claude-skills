import yaml
from flask import request
def f():
    return yaml.load(request.data)
