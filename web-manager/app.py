from datetime import timedelta

from flask import Flask, render_template
from flask_login import login_required

from blueprints import manager
from blueprints.auth import bp as auth_bp, login_manager
from db import init_db, get_or_create_secret_key

app = Flask(__name__)
app.secret_key = get_or_create_secret_key()
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)

login_manager.init_app(app)

app.register_blueprint(manager.bp)
app.register_blueprint(auth_bp)

with app.app_context():
    init_db()


@app.route('/')
@login_required
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
