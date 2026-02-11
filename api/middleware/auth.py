from functools import wraps
from flask import request, jsonify, current_app
import jwt
from datetime import datetime, timezone
import secrets
import hashlib


def generate_api_key():
    """Generate a secure API key"""
    random_bytes = secrets.token_bytes(32)
    api_key = hashlib.sha256(random_bytes).hexdigest()
    return f"sk_{api_key[:48]}"  # Stripe-style key


def verify_api_key(api_key):
    """Verify API key against database"""
    from app import get_db_connection

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT user_id, is_active, rate_limit, last_used 
            FROM api_keys 
            WHERE key_hash = ? AND is_active = 1
        ''', (hashlib.sha256(api_key.encode()).hexdigest(),))

        result = c.fetchone()

        if result:
            # Update last_used timestamp
            c.execute('''
                UPDATE api_keys 
                SET last_used = ?, request_count = request_count + 1 
                WHERE key_hash = ?
            ''', (datetime.now(timezone.utc), hashlib.sha256(api_key.encode()).hexdigest()))
            conn.commit()

            return {
                'user_id': result['user_id'],
                'rate_limit': result['rate_limit']
            }

    return None


def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key in header
        api_key = request.headers.get('X-API-Key')

        if not api_key:
            return jsonify({
                'error': 'API key missing',
                'message': 'Please provide X-API-Key header'
            }), 401

        # Verify API key
        key_data = verify_api_key(api_key)

        if not key_data:
            return jsonify({
                'error': 'Invalid API key',
                'message': 'The provided API key is invalid or inactive'
            }), 401

        # Attach user_id to request context
        request.api_user_id = key_data['user_id']
        request.rate_limit = key_data['rate_limit']

        return f(*args, **kwargs)

    return decorated_function


def require_jwt_token(f):
    """Decorator to require JWT token (alternative to API key)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'error': 'Token missing',
                'message': 'Please provide Bearer token in Authorization header'
            }), 401

        try:
            token = auth_header.split(' ')[1]
            data = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )

            request.api_user_id = data['user_id']
            return f(*args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({
                'error': 'Token expired',
                'message': 'Your token has expired. Please login again.'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'error': 'Invalid token',
                'message': 'The provided token is invalid'
            }), 401

    return decorated_function
