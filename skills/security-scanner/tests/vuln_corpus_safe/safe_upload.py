import os
from flask import request
from werkzeug.utils import secure_filename
def f():
    file = request.files['f']
    file.save(os.path.join('/uploads', secure_filename(file.filename)))
