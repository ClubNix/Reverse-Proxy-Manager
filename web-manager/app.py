from flask import Flask, render_template
from blueprints import manager

app = Flask(__name__)
app.register_blueprint(manager.bp)


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
