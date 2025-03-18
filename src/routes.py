from flask import Blueprint, render_template, request, redirect, url_for, session, send_file, flash, jsonify
import logging
import bcrypt
import os
import json
from dotenv import load_dotenv
from functools import wraps  # Import wraps
from datetime import datetime

# Load environment variables
load_dotenv()

routes = Blueprint('routes', __name__)
log_file = 'activity.log'
users_file = 'users.json'

logging.basicConfig(filename='activity.log', level=logging.INFO, format='%(asctime)s - %(message)s')
def log_activity(message, *args):
    logging.info(message, *args)

# Define default credentials
DEFAULT_ADMIN_USER = 'admin'
DEFAULT_ADMIN_PASS = 'admin'
DEFAULT_USER = 'user'
DEFAULT_USER_PASS = 'user'

# Get credentials from environment or use defaults
admin_username = os.getenv('ADMIN_USER', DEFAULT_ADMIN_USER)
admin_password = os.getenv('ADMIN_PASSWORD', DEFAULT_ADMIN_PASS)
user_username = os.getenv('REGULAR_USER', DEFAULT_USER)
user_password = os.getenv('USER_PASSWORD', DEFAULT_USER_PASS)

# Initialize users data store
def initialize_users():
    if not os.path.exists(users_file):
        users = {
            admin_username: {
                "password": admin_password,
                "role": "admin",
                "email": "admin@example.com",
                "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "last_login": "",
                "status": "active"
            },
            user_username: {
                "password": user_password,
                "role": "Standard User",
                "email": "user@example.com",
                "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "last_login": "",
                "status": "active"
            }
        }
        with open(users_file, 'w') as f:
            json.dump(users, f, indent=4)
    return load_users()

def load_users():
    try:
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                return json.load(f)
        return initialize_users()
    except:
        return initialize_users()

def save_users(users):
    with open(users_file, 'w') as f:
        json.dump(users, f, indent=4)

# Load users at startup
USERS = load_users()

# Function to check if a user exists and verify password
def verify_password(username, password):
    users = load_users()
    if username in users and users[username]["status"] == "active":
        return users[username]["password"] == password, users[username]["role"]
    return False, None

def login_required(f):
    """Decorator to restrict access to logged-in users."""
    @wraps(f)  # Use wraps to preserve the original function's name and docstring
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('routes.home', error='You must be logged in to access this page.'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    """Decorator to restrict access to users with a specific role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                log_activity('User %s attempted to access %s without proper permissions', 
                           session.get('user', 'Unknown'), request.path)
                return redirect(url_for('routes.dashboard', error='You do not have permission to access this page.'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@routes.route('/')
def home():
    error = request.args.get('error')
    return render_template('login.html', error=error)

@routes.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    ip_address = request.remote_addr
    last_login = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    is_valid, role = verify_password(username, password)
    
    if is_valid:
        log_activity('User %s logged in successfully from IP: %s at %s', username, ip_address, last_login)
        
        # Update last login time
        users = load_users()
        users[username]["last_login"] = last_login
        save_users(users)
        
        session['user'] = username
        session['role'] = role
        session['last_login'] = last_login
        session['ip_address'] = ip_address
        return redirect(url_for('routes.dashboard'))
    else:
        log_activity('Login failed for user %s from IP: %s at %s', username, ip_address, last_login)
        return redirect(url_for('routes.home', error='Incorrect details'))

@routes.route('/dashboard')
@login_required
def dashboard():
    error = request.args.get('error')
    log_activity('User %s accessed the dashboard', session['user'])
    return render_template('dashboard.html', error=error)

@routes.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('routes.home'))

@routes.route('/logs')
@login_required
def view_logs():
    """Reads and displays logs from activity.log"""
    log_activity('User %s accessed the logs', session['user'])

    if not os.path.exists(log_file):
        return "Log file not found", 404

    with open(log_file, 'r') as file:
        logs = file.readlines()  # Read log file

    return render_template('logs.html', logs=logs)

@routes.route('/download-logs')
@login_required
@role_required('admin')  # Only allow admins to download logs
def download_logs():
    """Serves the log file as a downloadable attachment"""
    log_activity('Admin %s downloaded the logs', session['user'])

    if not os.path.exists(log_file):
        return "Log file not found", 404

    return send_file(log_file, as_attachment=True)

@routes.route('/clear-logs', methods=['POST'])
@login_required
@role_required('admin')
def clear_logs():
    """Deletes the log file."""

    if os.path.exists(log_file):
        open(log_file, 'w').close()  # Clears the file
        log_activity('Admin %s cleared the logs', session['user'])
    
    return redirect(url_for('routes.view_logs'))

@routes.route('/profile')
@login_required
def profile():
    """Displays user details"""
    users = load_users()
    user_info = users.get(session.get('user'), {})
    
    return render_template('profile.html', 
                          user=session.get('user'), 
                          role=session.get('role'), 
                          last_login=session.get('last_login'),
                          email=user_info.get('email', ''))

@routes.route('/adminpage')
@login_required
@role_required('admin')
def some_protected_route():
    """Admin panel page"""
    log_activity('Admin %s accessed the admin panel', session['user'])
    return render_template('admin.html')

# User management routes
@routes.route('/users')
@login_required
@role_required('admin')
def manage_users():
    """User management page"""
    log_activity('Admin %s accessed the user management page', session['user'])
    users = load_users()
    return render_template('users.html', users=users)

@routes.route('/users/add', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    """Add a new user"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']
        
        users = load_users()
        
        if username in users:
            return render_template('add_user.html', error="Username already exists")
        
        users[username] = {
            "password": password,
            "role": role,
            "email": email,
            "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "last_login": "",
            "status": "active"
        }
        
        save_users(users)
        log_activity('Admin %s added a new user: %s', session['user'], username)
        
        return redirect(url_for('routes.manage_users'))
    
    return render_template('add_user.html')

@routes.route('/users/edit/<username>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(username):
    """Edit an existing user"""
    users = load_users()
    
    if username not in users:
        return redirect(url_for('routes.manage_users'))
    
    if request.method == 'POST':
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']
        status = request.form['status']
        
        if password:
            users[username]["password"] = password
        
        users[username]["email"] = email
        users[username]["role"] = role
        users[username]["status"] = status
        
        save_users(users)
        log_activity('Admin %s updated user: %s', session['user'], username)
        
        return redirect(url_for('routes.manage_users'))
    
    return render_template('edit_user.html', username=username, user_info=users[username])

@routes.route('/users/delete/<username>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(username):
    """Delete a user"""
    users = load_users()
    
    if username in users and username != session['user']:  # Prevent self-deletion
        del users[username]
        save_users(users)
        log_activity('Admin %s deleted user: %s', session['user'], username)
    
    return redirect(url_for('routes.manage_users'))
