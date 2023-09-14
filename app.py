from flask import Flask, render_template

app = Flask(__name__, template_folder='Templates', static_folder='Static')

@app.route('/')
def home():
    return "Hello, World!"

@app.route('/Welcome')
def index():
    return render_template('index.html')

if __name__=='__main__':
    app.run(debug = True)