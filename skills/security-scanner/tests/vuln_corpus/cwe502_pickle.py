import pickle
from flask import request
def f():
    return pickle.loads(request.data)
