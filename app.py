from flask import Flask, request, redirect, jsonify, make_response, request, render_template, session, flash, g
import jwt
import json
from datetime import datetime, timedelta
from functools import wraps
import sqlite3

app = Flask(__name__)

DATABASE = './DATABASE.db'

app.config['SECRET_KEY'] = '13w7FOvuHUXZwu3A+ljJ1ahlx0HFILSwQGugkOTx4MI='

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.before_first_request
def create_tables():
    db = get_db()
    create_users_table(db)
    
def create_users_table(db):
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password TEXT)")
    db.commit()
    
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def protected_route(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'Alert!': 'Authenticaion required!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'Message': 'Invalid token'}), 403
        return func(*args, **kwargs)
    return decorated


@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return render_template('dashboard.html')

@app.route('/api/books')
@protected_route
def get_books():
    with open('books.json', 'r') as file:
        book_data = json.load(file)
    return jsonify(book_data)

@app.route('/api/token')
@protected_route
def get_token():
    token = request.cookies.get('token')
    return jsonify({"jwt_token": token})


@app.route('/dashboard')
@protected_route
def dashboard():
    return render_template("dashboard.html")

# Just to show you that a public route is available for everyone
@app.route('/public')
def public():
    return 'For Public'

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form['email']
    password = request.form['password']

    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
    db.commit()

    return jsonify({'message': 'User registered successfully'})

# Login page
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
    user = cursor.fetchone()
    if user:
        session['logged_in'] = True

        token = jwt.encode({
            'user': email,
            'expiration': str(datetime.utcnow() + timedelta(seconds=600))
        }, app.config['SECRET_KEY'])
        response = redirect("/dashboard")
        response.set_cookie('token', token.decode('utf-8'), httponly=True)

        return response
    else:
        return make_response('Invalid credentials, please input correct email and password.', 403, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # Clear the session data
    response = redirect("/")
    response.set_cookie('token', '', expires=0)
    return response

if __name__ == "__main__":
    app.run(debug=True)
