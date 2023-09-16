from google.oauth2 import service_account
from googleapiclient.discovery import build
from flask import Flask, render_template, redirect, url_for, request, session
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
import MySQLdb.cursors
import re

app = Flask(__name__, template_folder='Templates', static_folder='Static')
app.secret_key = 'hellodarknite' 

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Hellodarknite@7@localhost/applogin' 
db = SQLAlchemy(app)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  
app.config['MYSQL_PASSWORD'] = 'Hellodarknite@7'  
app.config['MYSQL_DB'] = 'applogin'

mysql = MySQL(app)

# Function to fetch emails from Gmail using the Gmail API
def fetch_emails(gmail_service):
    results = gmail_service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    messages = results.get('messages', [])

    emails = []

    for message in messages:
        msg = gmail_service.users().messages().get(userId='me', id=message['id']).execute()
        email_data = {
            'sender': None,
            'subject': None,
            'body': None,
            'timestamp': None
        }

        for header in msg['payload']['headers']:
            if header['name'] == 'From':
                email_data['sender'] = header['value']
            elif header['name'] == 'Subject':
                email_data['subject'] = header['value']
            elif header['name'] == 'Date':
                email_data['timestamp'] = header['value']

        email_data['body'] = msg['snippet']
        emails.append(email_data)

    return emails

# Store Emails in MySQL Database
@app.route('/store_emails')
def store_emails():
    # Load Gmail API credentials from JSON file
    credentials = service_account.Credentials.from_service_account_file(
        'flaksapp-f7ba1924fc08.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly']
    )

    # Create a Gmail service
    gmail_service = build('gmail', 'v1', credentials=credentials)

    # Fetch emails from Gmail
    emails = fetch_emails(gmail_service)

    # Store emails in the MySQL database
    for email_data in emails:
        email = Email(
            sender=email_data['sender'],
            subject=email_data['subject'],
            body=email_data['body'],
            timestamp=email_data['timestamp']
        )
        db.session.add(email)

    db.session.commit()

    return 'Emails stored in the database'

# Your existing routes...

# Define a model for storing emails in the database
class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(255))
    subject = db.Column(db.String(255))
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime)


@app.route('/index')
def index():
    emails = Email.query.all()
    return render_template('index.html', emails=emails)

@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM account WHERE username = %s AND password = %s', (username, password,))
        account = cursor.fetchone()
        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            msg = 'Logged in successfully!'
            return render_template('index.html', msg=msg)
        else:
            msg = 'Incorrect username / password!'
    return render_template('login.html', msg=msg)

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM account WHERE username = %s', (username,))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            cursor.execute('INSERT INTO account (username, password, email) VALUES (%s, %s, %s)', (username, password, email,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)

if __name__ == '__main__':
    app.run(debug=True)