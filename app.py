# A backend api application that authenticates users, redirects them to their dashboards

from flask import Flask, request, redirect, jsonify, make_response, request, render_template, session, flash, g
import jwt
import json
from datetime import datetime, timedelta
from functools import wraps
import sqlite3

# Creating an instance of our app
app = Flask(__name__)

# This variable store the path of database so that we can access it later
DATABASE = './DATABASE.db'

# Secret Key for authentication
app.config['SECRET_KEY'] = '13w7FOvuHUXZwu3A+ljJ1ahlx0HFILSwQGugkOTx4MI='

# Establishing database conn
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Creating the table before first request is encountered
@app.before_first_request
def create_tables():
    db = get_db()
    create_users_table(db)
    
# Creating the `users` table
def create_users_table(db):
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password TEXT)")
    db.commit()
    
# Making sure that the conn is closed after app context is torn down
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# A decorator that can be applied to route functions to protect 'em with authentication
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

# Route for `home`. If user is logged in, will be able to access dashboard, else redirected to login
@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return render_template('dashboard.html')

# This route is protected using the `@protected_route` decorator. Books are returned on authentication
@app.route('/api/books')
@protected_route
def get_books():
    with open('books.json', 'r') as file:
        book_data = json.load(file)
    return jsonify(book_data)

# Getting the jwt token if authorised
@app.route('/api/token')
@protected_route
def get_token():
    token = request.cookies.get('token')
    return jsonify({"jwt_token": token})

# Dashboard route. Protected so that can be accessed only post authentication
@app.route('/dashboard')
@protected_route
def dashboard():
    return render_template("dashboard.html")

# Public route
@app.route('/public')
def public():
    return 'For Public'

# Signup route that retrieves information from the form using http POST request, establishes db conn and
# updates the credentials in the db
@app.route('/signup', methods=['POST'])
def signup():
    email = request.form['email']
    password = request.form['password']

    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
    db.commit()

    return jsonify({'message': 'User registered successfully'})

# Login page : fetches entered credentials from the form, verifies with the db.
# If user exists :
# 1) `logged_in` session variable is set to True
# 2) jwt token generated
# 3) Token is set as a cookie 
# 4) Redirectec to dashboard template
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
        response.set_cookie('token', token, httponly=True) #.decode('utf-8')

        return response
    else:
        return make_response('Invalid credentials, please input correct email and password.', 403, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})

# Logout route : Session is cleared, token cookie deleted and user redirected to `/`
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # Clear the session data
    response = redirect("/")
    response.set_cookie('token', '', expires=0)
    return response

# Starting our application
if __name__ == "__main__":
    app.run(debug=True)
