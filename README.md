# CS-Ia (Task Maker)

Flask web app built as an IB Computer Science project.
Connects to Gmail using Google OAuth and stores unread messages in a MySQL database.

## Features
- Google OAuth to read Gmail messages
- Store messages in MySQL
- Simple user register/login
- Dashboard for viewing emails

## Setup
1. Clone the repo and enter the folder.
2. Copy `.env.example` to `.env` and fill in values (do not commit `.env`).
3. Install dependencies: `pip install -r requirements.txt`
4. Run: `flask run` or `python app.py`
5. Open http://localhost:5000

## Important
Do NOT commit `.env` or `client_secret.json`.
Create your own Google OAuth credentials and set `OAUTH_CLIENT_SECRETS_PATH` in `.env`.

Author: mahouboy23
