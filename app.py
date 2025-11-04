from flask import Flask
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.discovery import build
from flask import Flask, render_template, redirect, url_for, request, session
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_
from google.oauth2.credentials import Credentials
from datetime import datetime
import MySQLdb.cursors
import re
import base64
import datetime
from flask_migrate import Migrate
import os

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__, template_folder='Templates', static_folder='Static')
app.secret_key = os.getenv('SECRET_KEY', 'dev_key')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'mysql://root:password@localhost:3306/applogin')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'applogin')

mysql = MySQL(app)

flow = Flow.from_client_secrets_file(os.getenv('OAUTH_CLIENT_SECRETS_PATH', 'client_secret.json'))

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(os.getenv('OAUTH_CLIENT_SECRETS_PATH', 'client_secret.json'))
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

class Email(db.Model):
    __tablename__ = 'emails'
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(255))
    subject = db.Column(db.String(255))
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime)
    body_html = db.Column(db.Text)

    def __init__(self, sender, subject, body, body_html, timestamp):
        self.sender = sender
        self.subject = subject
        self.body = body
        self.timestamp = timestamp
        self.body_html = body_html  
        
def remove_old_duplicates():
    """
    Remove old duplicate emails from the database based on sender, subject, and timestamp.
    """
    unique_emails = db.session.query(
        Email.sender, Email.subject, Email.timestamp, db.func.min(Email.id)
    ).group_by(Email.sender, Email.subject, Email.timestamp).all()

    duplicate_ids = []
    for sender, subject, timestamp, min_id in unique_emails:
        duplicate_ids.extend(
            db.session.query(Email.id).filter(
                and_(
                    Email.sender == sender,
                    Email.subject == subject,
                    Email.timestamp == timestamp,
                    Email.id != min_id  
                )
            ).all()
        )

    for duplicate_id in duplicate_ids:
        Email.query.filter_by(id=duplicate_id[0]).delete()

    db.session.commit()

@app.route('/oauth2callback')
def oauth2callback():
    if 'state' not in session:
        return redirect(url_for('login'))
    
    received_state = request.args.get('state')

    if received_state != session['state']:
        return "Invalid state parameter. Possible CSRF attack."

    state = session['state']
    flow.fetch_token(authorization_response=request.url, state=state)
    credentials = flow.credentials

    gmail_service = build('gmail', 'v1', credentials=credentials)

    results = gmail_service.users().messages().list(userId='me', q='is:unread').execute()
    messages = results.get('messages', [])

    for message in messages:
        msg = gmail_service.users().messages().get(userId='me', id=message['id']).execute()
        existing_email = Email.query.filter_by(id=msg['id']).first()

        if existing_email:
            continue  
        
        email_data = {
            'sender': None,
            'subject': None,
            'body': None,
            'timestamp': None,
            'body_html': None
        }

        for header in msg['payload']['headers']:
            if header['name'] == 'From':
                email_data['sender'] = header['value']
            elif header['name'] == 'Subject':
                email_data['subject'] = header['value']
            elif header['name'] == 'Date':
                date_str = header['value'].replace('GMT', '+0000')
                email_data['timestamp'] = datetime.datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")

        for part in msg['payload']['parts']:
            if part['mimeType'] == 'text/html':
                email_data['body_html'] = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')

        email = Email(
            sender=email_data['sender'],
            subject=email_data['subject'],
            body=email_data['body'],
            timestamp=email_data['timestamp'],
            body_html=email_data['body_html']  
        )
        try:
            db.session.add(email)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
        
        remove_old_duplicates()
            
    return redirect(url_for('index'))

@app.route('/refresh-emails')
def refresh_emails():
    # Check if the user has authorized the application
    if 'credentials' not in session:
        return redirect(url_for('login'))

    # Load credentials from the session
    creds = Credentials.from_authorized_user_info(session['credentials'])

    if not creds.valid:
        return redirect(url_for('login'))

    # Build the Gmail API service
    service = build('gmail', 'v1', credentials=creds)

    # Fetch emails
    results = service.users().messages().list(userId='me', q='is:unread').execute()
    messages = results.get('messages', [])

    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        existing_email = Email.query.filter_by(id=msg['id']).first()

        if existing_email:
            continue

        email_data = {
            'sender': None,
            'subject': None,
            'body': None,
            'timestamp': None,
            'body_html': None
        }

        for header in msg['payload']['headers']:
            if header['name'] == 'From':
                email_data['sender'] = header['value']
            elif header['name'] == 'Subject':
                email_data['subject'] = header['value']
            elif header['name'] == 'Date':
                date_str = header['value'].replace('GMT', '+0000')
                email_data['timestamp'] = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")

        for part in msg['payload']['parts']:
            if part['mimeType'] == 'text/html':
                email_data['body_html'] = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')

        email = Email(
            sender=email_data['sender'],
            subject=email_data['subject'],
            body=email_data['body'],
            timestamp=email_data['timestamp'],
            body_html=email_data['body_html']
        )
        try:
            db.session.add(email)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()

        remove_old_duplicates()

    # Redirect back to the index page
    return redirect(url_for('index'))

@app.route('/index')
def index():
    emails = Email.query.order_by(Email.timestamp.desc()).all()
    return render_template('index.html', emails=emails)

@app.route('/login_page', methods=['GET', 'POST'])
def login_page():
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

@app.route('/')
def entry():
    return render_template('entry.html')

if __name__ == '__main__':
    app.run(debug=True)