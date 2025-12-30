"""
Authentication Module for Case Log Management System
Handles login, logout, password hashing, JWT tokens, and account lockout
"""

import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session
from sqlalchemy import text

# JWT Secret Key (should be in environment variable in production)
JWT_SECRET = 'caselog-secret-key-change-in-production'
JWT_EXPIRY_HOURS = 24

# Account lockout settings
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 30


def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


def generate_token(user_data: dict) -> str:
    """Generate a JWT token for a user"""
    payload = {
        'user_id': user_data['id'],
        'eid': user_data['eid'],
        'role': user_data['role'],
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return {'success': True, 'data': payload}
    except jwt.ExpiredSignatureError:
        return {'success': False, 'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'success': False, 'error': 'Invalid token'}


def login_required(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Check for token in header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        # Check for token in session
        if not token:
            token = session.get('token')
        
        if not token:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        result = decode_token(token)
        if not result['success']:
            return jsonify({'success': False, 'error': result['error']}), 401
        
        # Add user info to request
        request.current_user = result['data']
        return f(*args, **kwargs)
    
    return decorated_function


def admin_required(f):
    """Decorator to require admin or superadmin role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if request.current_user.get('role') not in ['admin', 'superadmin']:
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    
    return decorated_function


def superadmin_required(f):
    """Decorator to require superadmin role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if request.current_user.get('role') != 'superadmin':
            return jsonify({'success': False, 'error': 'Superadmin access required'}), 403
        return f(*args, **kwargs)
    
    return decorated_function


def check_account_locked(user: dict) -> dict:
    """Check if user account is locked"""
    if user.get('is_locked') and user.get('locked_until'):
        locked_until = user['locked_until']
        if isinstance(locked_until, str):
            locked_until = datetime.fromisoformat(locked_until)
        
        if datetime.now() < locked_until:
            return {
                'locked': True,
                'locked_until': locked_until.strftime('%Y-%m-%d %H:%M:%S')
            }
        else:
            # Lock expired, will be cleared on successful login
            return {'locked': False}
    
    return {'locked': False}


def handle_failed_login(engine, user_id: int, current_attempts: int):
    """Handle a failed login attempt"""
    new_attempts = current_attempts + 1
    
    with engine.connect() as conn:
        if new_attempts >= MAX_FAILED_ATTEMPTS:
            # Lock the account
            locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            conn.execute(text("""
                UPDATE users 
                SET failed_attempts = :attempts, 
                    is_locked = TRUE, 
                    locked_until = :locked_until
                WHERE id = :user_id
            """), {
                'attempts': new_attempts,
                'locked_until': locked_until,
                'user_id': user_id
            })
        else:
            conn.execute(text("""
                UPDATE users 
                SET failed_attempts = :attempts
                WHERE id = :user_id
            """), {
                'attempts': new_attempts,
                'user_id': user_id
            })
        conn.commit()
    
    return {
        'attempts': new_attempts,
        'remaining': MAX_FAILED_ATTEMPTS - new_attempts,
        'locked': new_attempts >= MAX_FAILED_ATTEMPTS
    }


def clear_failed_attempts(engine, user_id: int):
    """Clear failed login attempts on successful login"""
    with engine.connect() as conn:
        conn.execute(text("""
            UPDATE users 
            SET failed_attempts = 0, 
                is_locked = FALSE, 
                locked_until = NULL
            WHERE id = :user_id
        """), {'user_id': user_id})
        conn.commit()


def get_user_locations(engine, user_id: int) -> list:
    """Get all locations a user has access to"""
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT ul.location_code, ul.can_view, ul.can_edit, ul.can_delete,
                   l.name, l.short_name
            FROM user_locations ul
            JOIN locations l ON ul.location_code = l.code
            WHERE ul.user_id = :user_id
        """), {'user_id': user_id})
        
        locations = []
        for row in result.fetchall():
            locations.append({
                'code': row[0],
                'can_view': row[1],
                'can_edit': row[2],
                'can_delete': row[3],
                'name': row[4],
                'short_name': row[5]
            })
        
        return locations


def check_location_permission(engine, user_id: int, location_code: str, permission: str) -> bool:
    """Check if user has specific permission for a location"""
    with engine.connect() as conn:
        result = conn.execute(text(f"""
            SELECT {permission} FROM user_locations 
            WHERE user_id = :user_id AND location_code = :location_code
        """), {'user_id': user_id, 'location_code': location_code})
        
        row = result.fetchone()
        return bool(row and row[0])
