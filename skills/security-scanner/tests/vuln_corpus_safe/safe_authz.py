from flask import Flask
from flask_login import login_required
app = Flask(__name__)
@app.route('/admin/delete_all', methods=['POST'])
@login_required
def delete_all():
    return 'deleted'
