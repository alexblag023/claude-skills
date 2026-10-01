from flask import Flask
app = Flask(__name__)
@app.route('/admin/delete_all', methods=['POST'])
def delete_all():
    return 'deleted'
