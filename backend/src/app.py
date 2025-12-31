from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from flask_cors import CORS
from sqlalchemy import create_engine, text
import pandas as pd
import os
import time
from io import BytesIO
from datetime import datetime, timedelta

from auth import (
    hash_password, verify_password, generate_token, decode_token,
    login_required, admin_required, check_account_locked,
    handle_failed_login, clear_failed_attempts, get_user_locations,
    check_location_permission
)
from email_utils import generate_otp, send_otp_email

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'caselog-secret-key-change-in-production')

# Config DB Connection - Support both local and Railway
user = os.environ.get('MYSQLUSER') or os.environ.get('DB_USER', 'case_user')
password = os.environ.get('MYSQLPASSWORD') or os.environ.get('DB_PASS', 'case_pass')
host = os.environ.get('MYSQLHOST') or os.environ.get('DB_HOST', 'localhost')
port = os.environ.get('MYSQLPORT') or os.environ.get('DB_PORT', '3306')
dbname = os.environ.get('MYSQLDATABASE') or os.environ.get('DB_NAME', 'caselog_db')

# Wait for DB to be ready (shorter wait on Railway)
wait_time = int(os.environ.get('DB_WAIT', '5'))
if wait_time > 0:
    time.sleep(wait_time)

db_str = f"mysql+pymysql://{user}:{password}@{host}:{port}/{dbname}"
engine = create_engine(db_str)

# Current location for API calls (default to hktmb)
def get_case_table(location_code='hktmb'):
    valid_locations = ['hktmb', 'hktcp', 'hktml', 'hktfp']
    if location_code not in valid_locations:
        location_code = 'hktmb'
    return f'case_logs_{location_code}'


def verify_location_access(location_code, permission='can_view'):
    """
    IDOR Prevention: Check if current user has access to the requested location.
    Returns tuple (has_access: bool, error_response: tuple or None)
    """
    user = getattr(request, 'current_user', None)
    if not user:
        return False, (jsonify({'success': False, 'error': 'Authentication required'}), 401)
    
    user_id = user.get('user_id')
    role = user.get('role', '')
    
    # Superadmin has access to all locations
    if role == 'superadmin':
        return True, None
    
    # Check user's location permissions
    has_permission = check_location_permission(engine, user_id, location_code, permission)
    if not has_permission:
        return False, (jsonify({'success': False, 'error': f'Access denied: No {permission} permission for location {location_code}'}), 403)
    
    return True, None

# ============ Auth Routes ============

@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        eid = data.get('eid', '').strip()
        pwd = data.get('password', '')
        
        if not eid or not pwd:
            return jsonify({'success': False, 'error': 'EID and password are required'})
        
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT id, eid, password_hash, email, full_name, role, 
                       is_locked, locked_until, failed_attempts
                FROM users WHERE eid = :eid
            """), {'eid': eid})
            user_row = result.fetchone()
        
        if not user_row:
            return jsonify({'success': False, 'error': 'Invalid EID or password'})
        
        user = {
            'id': user_row[0],
            'eid': user_row[1],
            'password_hash': user_row[2],
            'email': user_row[3],
            'full_name': user_row[4],
            'role': user_row[5],
            'is_locked': user_row[6],
            'locked_until': user_row[7],
            'failed_attempts': user_row[8]
        }
        
        # Check if account is locked
        lock_status = check_account_locked(user)
        if lock_status['locked']:
            return jsonify({
                'success': False,
                'error': 'Account is locked. Please contact admin or wait.',
                'locked_until': lock_status['locked_until']
            })
        
        # Verify password
        if not verify_password(pwd, user['password_hash']):
            result = handle_failed_login(engine, user['id'], user['failed_attempts'])
            
            if result['locked']:
                return jsonify({
                    'success': False,
                    'error': 'Account locked due to too many failed attempts. Please wait 30 minutes or contact admin.'
                })
            
            return jsonify({
                'success': False,
                'error': 'Invalid EID or password',
                'attempts_remaining': result['remaining']
            })
        
        # Successful login - clear failed attempts
        clear_failed_attempts(engine, user['id'])
        
        # Get user locations
        locations = get_user_locations(engine, user['id'])
        
        # Generate token
        token = generate_token(user)
        session['token'] = token
        session['user_id'] = user['id']
        
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': user['id'],
                'eid': user['eid'],
                'full_name': user['full_name'],
                'email': user['email'],
                'role': user['role'],
                'locations': locations
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/auth/verify', methods=['GET'])
def api_verify_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'success': False, 'error': 'No token provided'})
    
    token = auth_header.split(' ')[1]
    result = decode_token(token)
    
    if result['success']:
        return jsonify({'success': True, 'user': result['data']})
    else:
        return jsonify({'success': False, 'error': result['error']})


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@app.route('/api/auth/restore-session', methods=['POST'])
def restore_session():
    """Restore session from localStorage token (fixes redirect loop when session expires)"""
    try:
        data = request.get_json()
        token = data.get('token', '')
        
        if not token:
            return jsonify({'success': False, 'error': 'No token provided'})
        
        result = decode_token(token)
        if not result['success']:
            return jsonify({'success': False, 'error': result['error']})
        
        # Set session from token
        session['token'] = token
        session['user_id'] = result['data'].get('user_id')
        
        return jsonify({'success': True, 'message': 'Session restored'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============ OTP Routes ============

@app.route('/api/otp/request', methods=['POST'])
def request_otp():
    """Request OTP for registration or password reset"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        purpose = data.get('purpose', 'reset_password')  # 'register' or 'reset_password'
        
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'})
        
        if purpose not in ['register', 'reset_password']:
            return jsonify({'success': False, 'error': 'Invalid purpose'})
        
        with engine.connect() as conn:
            # For password reset, check if user exists
            if purpose == 'reset_password':
                user = conn.execute(text("SELECT id FROM users WHERE email = :email"), {'email': email}).fetchone()
                if not user:
                    return jsonify({'success': False, 'error': 'User with this email not found'})
            
            # Generate OTP
            otp_code = generate_otp()
            expires_at = datetime.now() + timedelta(minutes=10)
            
            # Delete old unused OTPs for this email
            conn.execute(text("DELETE FROM otp_tokens WHERE email = :email AND used = FALSE"), {'email': email})
            
            # Insert new OTP
            conn.execute(text("""
                INSERT INTO otp_tokens (email, otp_code, purpose, expires_at)
                VALUES (:email, :otp_code, :purpose, :expires_at)
            """), {'email': email, 'otp_code': otp_code, 'purpose': purpose, 'expires_at': expires_at})
            conn.commit()
        
        # Send OTP email
        result = send_otp_email(email, otp_code, purpose)
        
        if result['success']:
            return jsonify({'success': True, 'message': f'OTP sent to {email}'})
        else:
            return jsonify({'success': False, 'error': 'Failed to send OTP email'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/otp/verify', methods=['POST'])
def verify_otp():
    """Verify OTP code"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        otp_code = data.get('otp', '').strip()
        purpose = data.get('purpose', 'reset_password')
        
        if not email or not otp_code:
            return jsonify({'success': False, 'error': 'Email and OTP are required'})
        
        with engine.connect() as conn:
            # Find valid OTP
            otp_record = conn.execute(text("""
                SELECT id FROM otp_tokens 
                WHERE email = :email AND otp_code = :otp_code AND purpose = :purpose 
                AND expires_at > NOW() AND used = FALSE
                ORDER BY created_at DESC LIMIT 1
            """), {'email': email, 'otp_code': otp_code, 'purpose': purpose}).fetchone()
            
            if not otp_record:
                return jsonify({'success': False, 'error': 'Invalid or expired OTP'})
            
            # Mark OTP as used
            conn.execute(text("UPDATE otp_tokens SET used = TRUE WHERE id = :id"), {'id': otp_record[0]})
            conn.commit()
        
        return jsonify({'success': True, 'message': 'OTP verified successfully', 'verified': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/otp/reset-password', methods=['POST'])
def otp_reset_password():
    """Reset password after OTP verification"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        otp_code = data.get('otp', '').strip()
        new_password = data.get('new_password', '')
        
        if not email or not otp_code or not new_password:
            return jsonify({'success': False, 'error': 'Email, OTP, and new password are required'})
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'})
        
        with engine.connect() as conn:
            # Verify OTP
            otp_record = conn.execute(text("""
                SELECT id FROM otp_tokens 
                WHERE email = :email AND otp_code = :otp_code AND purpose = 'reset_password'
                AND expires_at > NOW() AND used = FALSE
                ORDER BY created_at DESC LIMIT 1
            """), {'email': email, 'otp_code': otp_code}).fetchone()
            
            if not otp_record:
                return jsonify({'success': False, 'error': 'Invalid or expired OTP'})
            
            # Get user
            user = conn.execute(text("SELECT id FROM users WHERE email = :email"), {'email': email}).fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'User not found'})
            
            # Update password
            password_hash = hash_password(new_password)
            conn.execute(text("""
                UPDATE users SET password_hash = :password_hash, is_locked = FALSE, locked_until = NULL, failed_attempts = 0
                WHERE id = :user_id
            """), {'password_hash': password_hash, 'user_id': user[0]})
            
            # Mark OTP as used
            conn.execute(text("UPDATE otp_tokens SET used = TRUE WHERE id = :id"), {'id': otp_record[0]})
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Password reset successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============ Web Routes ============

@app.route('/')
def index():
    # Check if logged in - try session first, then Authorization header
    token = session.get('token')
    
    # If no session token, check if there's an Authorization header (from JS redirect)
    if not token:
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
    
    if not token:
        return redirect(url_for('login_page'))
    
    result = decode_token(token)
    if not result['success']:
        session.clear()
        return redirect(url_for('login_page'))
    
    # Refresh session if token was from header
    if 'token' not in session:
        session['token'] = token
        session['user_id'] = result['data'].get('user_id')
    
    return render_template('index.html')

@app.route('/report')
def report():
    # Check if logged in - try session first, then Authorization header
    token = session.get('token')
    
    if not token:
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
    
    if not token:
        return redirect(url_for('login_page'))
    
    result = decode_token(token)
    if not result['success']:
        session.clear()
        return redirect(url_for('login_page'))
    
    # Refresh session if token was from header
    if 'token' not in session:
        session['token'] = token
        session['user_id'] = result['data'].get('user_id')
    
    return render_template('report.html')


@app.route('/admin')
def admin_page():
    # Check if logged in - try session first, then Authorization header
    token = session.get('token')
    
    if not token:
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
    
    if not token:
        return redirect(url_for('login_page'))
    
    result = decode_token(token)
    if not result['success']:
        session.clear()
        return redirect(url_for('login_page'))
    
    # Refresh session if token was from header
    if 'token' not in session:
        session['token'] = token
        session['user_id'] = result['data'].get('user_id')
    
    # Check role
    if result['data']['role'] not in ['admin', 'superadmin']:
        return redirect(url_for('index'))
    
    return render_template('admin.html')


# ============ Admin API Routes ============

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_admin_users():
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT u.id, u.eid, u.email, u.full_name, u.role, u.is_locked, u.locked_until, u.failed_attempts,
                       GROUP_CONCAT(ul.location_code) as locations
                FROM users u
                LEFT JOIN user_locations ul ON u.id = ul.user_id
                GROUP BY u.id
                ORDER BY u.role DESC, u.eid
            """))
            
            users = []
            for row in result.fetchall():
                users.append({
                    'id': row[0],
                    'eid': row[1],
                    'email': row[2],
                    'full_name': row[3],
                    'role': row[4],
                    'is_locked': bool(row[5]),
                    'locked_until': str(row[6]) if row[6] else None,
                    'failed_attempts': row[7],
                    'locations': row[8].split(',') if row[8] else []
                })
            
        return jsonify({'success': True, 'data': users})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/users', methods=['POST'])
@admin_required
def create_admin_user():
    try:
        data = request.get_json()
        eid = data.get('eid', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        full_name = data.get('full_name', '').strip() or f"{first_name} {last_name}".strip()
        position = data.get('position', None)
        phone = data.get('phone', '').strip()
        role = data.get('role', 'user')
        locations = data.get('locations', [])
        
        if not eid or not password:
            return jsonify({'success': False, 'error': 'EID and password are required'})
        
        # Strong password validation (12 chars minimum)
        import re
        strong_password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]).{12,}$'
        if not re.match(strong_password_regex, password):
            return jsonify({'success': False, 'error': 'Password must be at least 12 characters with uppercase, lowercase, number, and special character'})
        
        # Hash password
        password_hash = hash_password(password)
        
        with engine.connect() as conn:
            # Check if EID exists
            existing = conn.execute(text("SELECT id FROM users WHERE eid = :eid"), {'eid': eid}).fetchone()
            if existing:
                return jsonify({'success': False, 'error': 'EID already exists'})
            
            # Insert user with new fields
            result = conn.execute(text("""
                INSERT INTO users (eid, password_hash, email, first_name, last_name, full_name, position, phone, role)
                VALUES (:eid, :password_hash, :email, :first_name, :last_name, :full_name, :position, :phone, :role)
            """), {
                'eid': eid,
                'password_hash': password_hash,
                'email': email or None,
                'first_name': first_name or None,
                'last_name': last_name or None,
                'full_name': full_name or None,
                'position': position or None,
                'phone': phone or None,
                'role': role
            })
            conn.commit()
            
            user_id = result.lastrowid
            
            # Add location access
            for loc_code in locations:
                conn.execute(text("""
                    INSERT INTO user_locations (user_id, location_code, can_view, can_edit, can_delete)
                    VALUES (:user_id, :location_code, TRUE, TRUE, TRUE)
                """), {'user_id': user_id, 'location_code': loc_code})
            conn.commit()
        
        return jsonify({'success': True, 'message': 'User created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/users/<int:user_id>/unlock', methods=['POST'])
@admin_required
def unlock_admin_user(user_id):
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE users SET is_locked = FALSE, locked_until = NULL, failed_attempts = 0
                WHERE id = :user_id
            """), {'user_id': user_id})
            conn.commit()
        return jsonify({'success': True, 'message': 'User unlocked'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def reset_admin_password(user_id):
    try:
        data = request.get_json()
        new_password = data.get('password', '')
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'})
        
        password_hash = hash_password(new_password)
        
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE users SET password_hash = :password_hash, is_locked = FALSE, locked_until = NULL, failed_attempts = 0
                WHERE id = :user_id
            """), {'password_hash': password_hash, 'user_id': user_id})
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Password reset successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_admin_user(user_id):
    try:
        data = request.get_json()
        role = data.get('role', 'user')
        locations = data.get('locations', [])
        
        # Validate role
        if role not in ['user', 'admin']:
            return jsonify({'success': False, 'error': 'Invalid role'})
        
        with engine.connect() as conn:
            # Update user role
            conn.execute(text("""
                UPDATE users SET role = :role WHERE id = :user_id
            """), {'role': role, 'user_id': user_id})
            
            # Delete existing location permissions
            conn.execute(text("""
                DELETE FROM user_locations WHERE user_id = :user_id
            """), {'user_id': user_id})
            
            # Add new location permissions
            for loc_code in locations:
                conn.execute(text("""
                    INSERT INTO user_locations (user_id, location_code, can_view, can_edit, can_delete)
                    VALUES (:user_id, :location_code, TRUE, TRUE, TRUE)
                """), {'user_id': user_id, 'location_code': loc_code})
            
            conn.commit()
        
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_admin_user(user_id):
    try:
        with engine.connect() as conn:
            # Don't allow deleting superadmin
            user = conn.execute(text("SELECT role FROM users WHERE id = :id"), {'id': user_id}).fetchone()
            if user and user[0] == 'superadmin':
                return jsonify({'success': False, 'error': 'Cannot delete superadmin'})
            
            conn.execute(text("DELETE FROM user_locations WHERE user_id = :user_id"), {'user_id': user_id})
            conn.execute(text("DELETE FROM users WHERE id = :user_id"), {'user_id': user_id})
            conn.commit()
        
        return jsonify({'success': True, 'message': 'User deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/locations', methods=['GET'])
@admin_required
def get_admin_locations():
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT l.code, l.name, l.short_name, COUNT(u.id) as user_count
                FROM locations l
                LEFT JOIN user_locations ul ON l.code = ul.location_code
                LEFT JOIN users u ON ul.user_id = u.id AND u.role != 'superadmin'
                GROUP BY l.code
                ORDER BY l.name
            """))
            
            locations = []
            for row in result.fetchall():
                locations.append({
                    'code': row[0],
                    'name': row[1],
                    'short_name': row[2],
                    'user_count': row[3]
                })
        
        return jsonify({'success': True, 'data': locations})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/locations', methods=['POST'])
@admin_required
def create_admin_location():
    try:
        data = request.get_json()
        code = data.get('code', '').strip().lower()
        name = data.get('name', '').strip()
        short_name = data.get('short_name', '').strip()
        
        if not code or not name or not short_name:
            return jsonify({'success': False, 'error': 'All fields are required'})
        
        if len(code) < 3 or len(code) > 10:
            return jsonify({'success': False, 'error': 'Code must be 3-10 characters'})
        
        with engine.connect() as conn:
            # Check if code already exists
            existing = conn.execute(text("SELECT code FROM locations WHERE code = :code"), {'code': code}).fetchone()
            if existing:
                return jsonify({'success': False, 'error': 'Location code already exists'})
            
            conn.execute(text("""
                INSERT INTO locations (code, name, short_name)
                VALUES (:code, :name, :short_name)
            """), {'code': code, 'name': name, 'short_name': short_name})
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Location created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/locations/<string:code>', methods=['DELETE'])
@admin_required
def delete_admin_location(code):
    try:
        with engine.connect() as conn:
            # Delete user_locations first (foreign key)
            conn.execute(text("DELETE FROM user_locations WHERE location_code = :code"), {'code': code})
            # Delete location
            result = conn.execute(text("DELETE FROM locations WHERE code = :code"), {'code': code})
            conn.commit()
            
            if result.rowcount == 0:
                return jsonify({'success': False, 'error': 'Location not found'})
        
        return jsonify({'success': True, 'message': 'Location deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/users/by-location', methods=['GET'])
def get_users_by_location():
    """Get users that have access to a specific location (for resolver dropdown)"""
    try:
        location = request.args.get('location', 'hktmb')
        
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT u.eid, u.full_name, u.role
                FROM users u
                INNER JOIN user_locations ul ON u.id = ul.user_id
                WHERE ul.location_code = :location AND u.is_locked = FALSE
                ORDER BY u.full_name, u.eid
            """), {'location': location})
            
            users = []
            for row in result.fetchall():
                users.append({
                    'eid': row[0],
                    'full_name': row[1] or row[0],  # Use EID if no full name
                    'role': row[2],
                    'display': f"{row[1] or row[0]} ({row[0]})"  # Format: Full Name (EID)
                })
        
        return jsonify({'success': True, 'data': users})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============ API Routes ============

@app.route('/api/cases', methods=['GET'])
@login_required
def get_cases():
    try:
        location = request.args.get('location', 'hktmb')
        
        # IDOR Prevention: Check location access
        has_access, error_response = verify_location_access(location, 'can_view')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        status = request.args.get('status', '')
        department = request.args.get('department', '')
        issues = request.args.get('issues', '')
        from_date = request.args.get('from_date', '')
        to_date = request.args.get('to_date', '')
        search = request.args.get('search', '')
        limit = request.args.get('limit', '')
        
        query = f"SELECT * FROM {table_name} WHERE 1=1"
        count_query = f"SELECT COUNT(*) FROM {table_name} WHERE 1=1"
        params = {}
        
        if status:
            query += " AND status = :status"
            count_query += " AND status = :status"
            params['status'] = status
        if department:
            query += " AND department = :department"
            count_query += " AND department = :department"
            params['department'] = department
        if issues:
            query += " AND issues = :issues"
            count_query += " AND issues = :issues"
            params['issues'] = issues
        if from_date:
            query += " AND case_date >= :from_date"
            count_query += " AND case_date >= :from_date"
            params['from_date'] = from_date
        if to_date:
            query += " AND case_date <= :to_date"
            count_query += " AND case_date <= :to_date"
            params['to_date'] = to_date
        if search:
            query += " AND (case_no LIKE :search OR description LIKE :search OR opened_by LIKE :search OR step_to_resolve LIKE :search)"
            count_query += " AND (case_no LIKE :search OR description LIKE :search OR opened_by LIKE :search OR step_to_resolve LIKE :search)"
            params['search'] = f"%{search}%"
        
        query += " ORDER BY id DESC"
        
        # Add LIMIT if specified
        if limit and limit.isdigit():
            query += f" LIMIT {int(limit)}"
        
        with engine.connect() as conn:
            # Get total count first
            total = conn.execute(text(count_query), params).fetchone()[0]
            
            result = conn.execute(text(query), params)
            rows = result.fetchall()
            columns = result.keys()
            
            cases = []
            for row in rows:
                case = dict(zip(columns, row))
                for key in ['case_date', 'created_at', 'updated_at']:
                    if case.get(key):
                        case[key] = str(case[key])
                cases.append(case)
            
            return jsonify({'success': True, 'data': cases, 'total': total})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/cases/max-no', methods=['GET'])
@login_required
def get_max_case_no():
    try:
        location = request.args.get('location', 'hktmb')
        table_name = get_case_table(location)
        
        with engine.connect() as conn:
            # Get max case_no as integer (handles numeric strings)
            result = conn.execute(text(f"""
                SELECT COALESCE(MAX(CAST(case_no AS UNSIGNED)), 0) as max_no 
                FROM {table_name} 
                WHERE case_no REGEXP '^[0-9]+$'
            """))
            max_no = result.fetchone()[0]
            
        return jsonify({'success': True, 'data': {'max_no': max_no}})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/cases', methods=['POST'])
@login_required
def create_case():
    try:
        data = request.get_json()
        location = data.get('location', 'hktmb')
        
        # IDOR Prevention: Check location access
        has_access, error_response = verify_location_access(location, 'can_edit')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        # Auto-generate case_no if not provided
        case_no = data.get('case_no', '')
        if not case_no:
            with engine.connect() as conn:
                result = conn.execute(text(f"SELECT MAX(case_no) as max_no FROM {table_name}"))
                row = result.fetchone()
                max_no = row[0] if row and row[0] else 0
                try:
                    case_no = int(max_no) + 1
                except:
                    case_no = 1
        
        query = f"""
            INSERT INTO {table_name} 
            (case_no, case_date, issues, description, step_to_resolve, opened_by, department, status, resolved_by, remark)
            VALUES 
            (:case_no, :case_date, :issues, :description, :step_to_resolve, :opened_by, :department, :status, :resolved_by, :remark)
        """
        
        params = {
            'case_no': case_no,
            'case_date': data.get('case_date') or None,
            'issues': data.get('issues', ''),
            'description': data.get('description', ''),
            'step_to_resolve': data.get('step_to_resolve', ''),
            'opened_by': data.get('opened_by', ''),
            'department': data.get('department', ''),
            'status': data.get('status', 'In progress'),
            'resolved_by': data.get('resolved_by', ''),
            'remark': data.get('remark', '')
        }
        
        with engine.connect() as conn:
            conn.execute(text(query), params)
            conn.commit()
            
        return jsonify({'success': True, 'message': 'Case created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/cases/<int:case_id>', methods=['PUT'])
@login_required
def update_case(case_id):
    try:
        data = request.get_json()
        location = data.get('location', 'hktmb')
        
        # IDOR Prevention: Check location access
        has_access, error_response = verify_location_access(location, 'can_edit')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        query = f"""
            UPDATE {table_name} SET
                case_no = :case_no,
                case_date = :case_date,
                issues = :issues,
                description = :description,
                step_to_resolve = :step_to_resolve,
                opened_by = :opened_by,
                department = :department,
                status = :status,
                resolved_by = :resolved_by,
                remark = :remark
            WHERE id = :id
        """
        
        params = {
            'id': case_id,
            'case_no': data.get('case_no', ''),
            'case_date': data.get('case_date') or None,
            'issues': data.get('issues', ''),
            'description': data.get('description', ''),
            'step_to_resolve': data.get('step_to_resolve', ''),
            'opened_by': data.get('opened_by', ''),
            'department': data.get('department', ''),
            'status': data.get('status', 'In progress'),
            'resolved_by': data.get('resolved_by', ''),
            'remark': data.get('remark', '')
        }
        
        with engine.connect() as conn:
            conn.execute(text(query), params)
            conn.commit()
            
        return jsonify({'success': True, 'message': 'Case updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/cases/<int:case_id>', methods=['DELETE'])
@login_required
def delete_case(case_id):
    try:
        location = request.args.get('location', 'hktmb')
        
        # IDOR Prevention: Check location access
        has_access, error_response = verify_location_access(location, 'can_delete')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        with engine.connect() as conn:
            conn.execute(text(f"DELETE FROM {table_name} WHERE id = :id"), {'id': case_id})
            conn.commit()
            
        return jsonify({'success': True, 'message': 'Case deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/cases/all', methods=['DELETE'])
@admin_required
def delete_all_cases():
    try:
        location = request.args.get('location', 'hktmb')
        table_name = get_case_table(location)
        
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
            count = result.fetchone()[0]
            
            conn.execute(text(f"DELETE FROM {table_name}"))
            conn.commit()
            
        return jsonify({'success': True, 'message': f'Deleted {count} cases successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/export', methods=['GET'])
@login_required
def export_excel():
    try:
        location = request.args.get('location', 'hktmb')
        
        # IDOR Prevention
        has_access, error_response = verify_location_access(location, 'can_view')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        # Get filter parameters (same as get_cases)
        status = request.args.get('status', '')
        department = request.args.get('department', '')
        issues = request.args.get('issues', '')
        from_date = request.args.get('from_date', '')
        to_date = request.args.get('to_date', '')
        search = request.args.get('search', '')
        
        query = f"SELECT * FROM {table_name} WHERE 1=1"
        params = {}
        
        if status:
            query += " AND status = :status"
            params['status'] = status
        if department:
            query += " AND department = :department"
            params['department'] = department
        if issues:
            query += " AND issues = :issues"
            params['issues'] = issues
        if from_date:
            query += " AND case_date >= :from_date"
            params['from_date'] = from_date
        if to_date:
            query += " AND case_date <= :to_date"
            params['to_date'] = to_date
        if search:
            query += " AND (case_no LIKE :search OR description LIKE :search OR opened_by LIKE :search OR step_to_resolve LIKE :search)"
            params['search'] = f"%{search}%"
        
        query += " ORDER BY id ASC"
            
        with engine.connect() as conn:
            result = conn.execute(text(query), params)
            rows = result.fetchall()
            columns = result.keys()
            
        df = pd.DataFrame(rows, columns=columns)
        
        # Reset No. column to sequential numbers (1, 2, 3, ...)
        if len(df) > 0:
            df['case_no'] = range(1, len(df) + 1)
        
        # Rename columns to match original Excel format
        column_mapping = {
            'case_no': 'No.',
            'case_date': 'Date',
            'issues': 'Issues',
            'description': 'Description',
            'step_to_resolve': 'Step to Resolve',
            'opened_by': 'Opened by',
            'department': 'Department',
            'status': 'Status',
            'resolved_by': 'Resolved by',
            'remark': 'Remark'
        }
        df = df.rename(columns=column_mapping)
        
        # Keep only the Excel columns in correct order
        export_columns = ['No.', 'Date', 'Issues', 'Description', 'Step to Resolve', 
                          'Opened by', 'Department', 'Status', 'Resolved by', 'Remark']
        df = df[[col for col in export_columns if col in df.columns]]
        
        # Format Date column as text (D-MMM-YY format) to avoid Excel formula errors
        if 'Date' in df.columns:
            def format_date(d):
                if pd.isna(d) or d is None:
                    return ''
                try:
                    if hasattr(d, 'strftime'):
                        return d.strftime('%-d-%b-%y') if hasattr(d, 'strftime') else str(d)
                    return str(d)
                except:
                    return str(d)
            df['Date'] = df['Date'].apply(format_date)
        
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Case Logs')
            
            # Auto-adjust column widths
            worksheet = writer.sheets['Case Logs']
            for idx, col in enumerate(df.columns):
                max_length = max(
                    df[col].astype(str).map(len).max() if len(df) > 0 else 0,
                    len(col)
                ) + 2
                # Limit max width
                max_length = min(max_length, 50)
                worksheet.column_dimensions[chr(65 + idx)].width = max_length
        output.seek(0)
        
        filename = f"case_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/import', methods=['POST'])
@admin_required
def import_excel():
    try:
        location = request.form.get('location', 'hktmb')
        
        # IDOR Prevention
        has_access, error_response = verify_location_access(location, 'can_edit')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        df = pd.read_excel(file, engine='openpyxl')
        
        # Map Excel column names to database columns
        column_mapping = {
            'No.': 'case_no',
            'Date': 'case_date',
            'Issues': 'issues',
            'Description': 'description',
            'Step to Resolve': 'step_to_resolve',
            'Opened by': 'opened_by',
            'Department': 'department',
            'Status': 'status',
            'Resolved by': 'resolved_by',
            'Remark': 'remark'
        }
        
        df = df.rename(columns=column_mapping)
        
        valid_columns = ['case_no', 'case_date', 'issues', 'description', 'step_to_resolve',
                         'opened_by', 'department', 'status', 'resolved_by', 'remark']
        df = df[[col for col in valid_columns if col in df.columns]]
        
        # Drop rows where case_no is empty/null (these are empty rows)
        if 'case_no' in df.columns:
            df = df.dropna(subset=['case_no'])
        
        inserted = 0
        skipped = 0
        with engine.connect() as conn:
            for _, row in df.iterrows():
                data = row.to_dict()
                
                # Skip if case_no is empty
                if not data.get('case_no') or pd.isna(data.get('case_no')):
                    skipped += 1
                    continue
                
                # Skip rows that only have a sequence number but no actual data
                # Must have at least one of: issues, description, opened_by, or department
                has_data = False
                for field in ['issues', 'description', 'opened_by', 'department', 'case_date']:
                    val = data.get(field)
                    if val is not None and not pd.isna(val) and str(val).strip() != '':
                        has_data = True
                        break
                
                if not has_data:
                    skipped += 1
                    continue
                
                # Handle date conversion - check for NaT (Not a Time)
                if 'case_date' in data:
                    if pd.isna(data['case_date']) or data['case_date'] is None:
                        data['case_date'] = None
                    elif isinstance(data['case_date'], str):
                        date_parsed = False
                        # Try multiple date formats
                        for fmt in ['%Y-%m-%d', '%d-%b-%y', '%d/%m/%Y', '%m/%d/%Y', '%d-%m-%Y']:
                            try:
                                data['case_date'] = datetime.strptime(data['case_date'], fmt).date()
                                date_parsed = True
                                break
                            except:
                                continue
                        if not date_parsed:
                            data['case_date'] = None
                    elif hasattr(data['case_date'], 'date'):
                        # It's a datetime/Timestamp object
                        data['case_date'] = data['case_date'].date()
                
                # Convert case_no to string
                if 'case_no' in data and data['case_no'] is not None:
                    if isinstance(data['case_no'], float):
                        data['case_no'] = str(int(data['case_no']))
                    else:
                        data['case_no'] = str(data['case_no'])
                
                # Handle all other fields - convert NaN/NaT to None
                for col in valid_columns:
                    if col in data and pd.isna(data[col]):
                        data[col] = None
                
                data.setdefault('status', 'In progress')
                
                query = f"""
                    INSERT INTO {table_name} 
                    (case_no, case_date, issues, description, step_to_resolve, opened_by, department, status, resolved_by, remark)
                    VALUES 
                    (:case_no, :case_date, :issues, :description, :step_to_resolve, :opened_by, :department, :status, :resolved_by, :remark)
                """
                
                params = {col: data.get(col) for col in valid_columns}
                conn.execute(text(query), params)
                inserted += 1
            
            conn.commit()
        
        return jsonify({'success': True, 'message': f'Imported {inserted} records successfully (skipped {skipped} empty rows)'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    try:
        location = request.args.get('location', 'hktmb')
        
        # IDOR Prevention
        has_access, error_response = verify_location_access(location, 'can_view')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        # Get filter parameters
        status = request.args.get('status', '')
        department = request.args.get('department', '')
        issues = request.args.get('issues', '')
        from_date = request.args.get('from_date', '')
        to_date = request.args.get('to_date', '')
        search = request.args.get('search', '')
        
        # Build filter conditions
        conditions = "WHERE 1=1"
        params = {}
        
        if department:
            conditions += " AND department = :department"
            params['department'] = department
        if issues:
            conditions += " AND issues = :issues"
            params['issues'] = issues
        if from_date:
            conditions += " AND case_date >= :from_date"
            params['from_date'] = from_date
        if to_date:
            conditions += " AND case_date <= :to_date"
            params['to_date'] = to_date
        if search:
            conditions += " AND (case_no LIKE :search OR description LIKE :search OR opened_by LIKE :search)"
            params['search'] = f"%{search}%"
        
        with engine.connect() as conn:
            total = conn.execute(text(f"SELECT COUNT(*) FROM {table_name} {conditions}"), params).fetchone()[0]
            in_progress = conn.execute(text(f"SELECT COUNT(*) FROM {table_name} {conditions} AND status = 'In progress'"), params).fetchone()[0]
            completed = conn.execute(text(f"SELECT COUNT(*) FROM {table_name} {conditions} AND status = 'Completed'"), params).fetchone()[0]
            this_month = conn.execute(text(f"""
                SELECT COUNT(*) FROM {table_name} {conditions}
                AND MONTH(case_date) = MONTH(CURDATE()) AND YEAR(case_date) = YEAR(CURDATE())
            """), params).fetchone()[0]
            
        return jsonify({
            'success': True,
            'data': {
                'total': total,
                'in_progress': in_progress,
                'completed': completed,
                'this_month': this_month
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/departments', methods=['GET'])
@login_required
def get_departments():
    try:
        location = request.args.get('location', 'hktmb')
        
        # IDOR Prevention
        has_access, error_response = verify_location_access(location, 'can_view')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT DISTINCT department FROM {table_name} WHERE department IS NOT NULL AND department != '' ORDER BY department"))
            departments = [row[0] for row in result.fetchall()]
        return jsonify({'success': True, 'data': departments})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/issues', methods=['GET'])
@login_required
def get_issues():
    try:
        location = request.args.get('location', 'hktmb')
        
        # IDOR Prevention
        has_access, error_response = verify_location_access(location, 'can_view')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT DISTINCT issues FROM {table_name} WHERE issues IS NOT NULL AND issues != '' ORDER BY issues"))
            issues = [row[0] for row in result.fetchall()]
        return jsonify({'success': True, 'data': issues})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/report', methods=['GET'])
@login_required
def get_report():
    try:
        location = request.args.get('location', 'hktmb')
        
        # IDOR Prevention
        has_access, error_response = verify_location_access(location, 'can_view')
        if not has_access:
            return error_response
        
        table_name = get_case_table(location)
        
        from_date = request.args.get('from_date', '')
        to_date = request.args.get('to_date', '')
        department = request.args.get('department', '')
        
        # Base query conditions
        conditions = "WHERE 1=1"
        params = {}
        
        if from_date:
            conditions += " AND case_date >= :from_date"
            params['from_date'] = from_date
        if to_date:
            conditions += " AND case_date <= :to_date"
            params['to_date'] = to_date
        if department:
            conditions += " AND department = :department"
            params['department'] = department
        
        with engine.connect() as conn:
            # Summary
            total = conn.execute(text(f"SELECT COUNT(*) FROM {table_name} {conditions}"), params).fetchone()[0]
            completed = conn.execute(text(f"SELECT COUNT(*) FROM {table_name} {conditions} AND status = 'Completed'"), params).fetchone()[0]
            in_progress = conn.execute(text(f"SELECT COUNT(*) FROM {table_name} {conditions} AND status = 'In progress'"), params).fetchone()[0]
            
            # Group by Issues
            by_issues_result = conn.execute(text(f"""
                SELECT issues, COUNT(*) as count 
                FROM {table_name} {conditions} AND issues IS NOT NULL AND issues != ''
                GROUP BY issues 
                ORDER BY count DESC
            """), params)
            by_issues = [{'name': row[0], 'count': row[1]} for row in by_issues_result.fetchall()]
            
            # Group by Department
            by_dept_result = conn.execute(text(f"""
                SELECT department, COUNT(*) as count 
                FROM {table_name} {conditions} AND department IS NOT NULL AND department != ''
                GROUP BY department 
                ORDER BY count DESC
            """), params)
            by_department = [{'name': row[0], 'count': row[1]} for row in by_dept_result.fetchall()]
            
            # Group by Resolver - Split comma-separated values for individual counting
            by_resolver_result = conn.execute(text(f"""
                SELECT resolved_by
                FROM {table_name} {conditions} AND resolved_by IS NOT NULL AND resolved_by != ''
            """), params)
            
            # Count each resolver individually (split comma-separated values)
            # Filter out placeholder values like "--- Please Select ---"
            placeholder_values = ['--- Please Select ---', '---', 'Please Select', '']
            resolver_counts = {}
            for row in by_resolver_result.fetchall():
                resolvers = [r.strip() for r in row[0].split(',') if r.strip()]
                for resolver in resolvers:
                    if resolver not in placeholder_values:
                        resolver_counts[resolver] = resolver_counts.get(resolver, 0) + 1
            
            # Sort by count descending
            by_resolver = [{'name': name, 'count': count} 
                          for name, count in sorted(resolver_counts.items(), key=lambda x: x[1], reverse=True)]
            
            # Group by Date (trend)
            by_date_result = conn.execute(text(f"""
                SELECT DATE(case_date) as date, COUNT(*) as count 
                FROM {table_name} {conditions} AND case_date IS NOT NULL
                GROUP BY DATE(case_date) 
                ORDER BY date ASC
            """), params)
            by_date = [{'date': str(row[0]), 'name': str(row[0]), 'count': row[1]} for row in by_date_result.fetchall()]
        
        return jsonify({
            'success': True,
            'data': {
                'summary': {
                    'total': total,
                    'completed': completed,
                    'in_progress': in_progress
                },
                'by_issues': by_issues,
                'by_department': by_department,
                'by_resolver': by_resolver,
                'by_date': by_date
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/locations', methods=['GET'])
def get_locations():
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT code, name, short_name FROM locations ORDER BY name"))
            locations = []
            for row in result.fetchall():
                locations.append({
                    'code': row[0],
                    'name': row[1],
                    'short_name': row[2]
                })
        return jsonify({'success': True, 'data': locations})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

