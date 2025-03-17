from flask import Blueprint, render_template, request, redirect, url_for, session, send_file, flash
import logging
import bcrypt
import os
from dotenv import load_dotenv
from functools import wraps  # Import wraps
from datetime import datetime

# Load environment variables
load_dotenv()

routes = Blueprint('routes', __name__)
log_file = 'activity.log'

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

# Function to check if a user exists and verify password
def verify_password(username, password):
    if username == admin_username:
        return password == admin_password, 'admin'
    elif username == user_username:
        return password == user_password, 'Standard User'
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
    return render_template('profile.html', user=session.get('user'), role=session.get('role'), last_login=session.get('last_login'))

@routes.route('/adminpage')
@login_required
@role_required('admin')
def some_protected_route():
    """Admin panel page"""
    log_activity('Admin %s accessed the admin panel', session['user'])
    return render_template('admin.html')
