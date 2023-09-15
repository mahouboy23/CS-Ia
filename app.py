from flask import Flask, render_template, redirect, url_for, request

app = Flask(__name__, template_folder='Templates', static_folder='Static')

@app.route('/')
def index(name=None):
    return render_template('index.html', name=name)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            return redirect(url_for('index'))
    return render_template('login.html', error=error)

if __name__=='__main__':
    app.run(debug = True)