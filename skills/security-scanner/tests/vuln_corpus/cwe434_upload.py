from flask import request
def f():
    file = request.files['f']
    file.save('/uploads/' + file.filename)
