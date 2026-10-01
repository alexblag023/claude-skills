from flask import request, render_template_string
def f():
    return render_template_string('Hello ' + request.args['n'])
