import yaml
from flask import request
def f():
    return yaml.safe_load(request.data)
