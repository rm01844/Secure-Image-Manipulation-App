from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime, timezone
from api.routes.auth import auth_bp
from api.routes.images import images_bp
from app import app as web_app, init_db, db, genai_client
import os

# Create API app or extend existing app
app = web_app  # Reuse existing Flask app

# Enable CORS for API routes
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-API-Key"]
    }
})

# Register API blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(images_bp)

# API root endpoint


@app.route('/api/v1', methods=['GET'])
def api_root():
    """API information endpoint"""
    return jsonify({
        'name': 'Image Manipulation API',
        'version': '1.0.0',
        'description': 'AI-powered image editing API with company t-shirt application',
        'documentation': '/api/v1/docs',
        'endpoints': {
            'authentication': '/api/v1/auth',
            'images': '/api/v1/images'
        },
        'authentication_methods': [
            'API Key (X-API-Key header)',
            'JWT Token (Bearer token)'
        ],
        'support': {
            'email': 'support@your-domain.com',
            'documentation': 'https://docs.your-domain.com'
        }
    }), 200

# API health check


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '1.0.0',
        'services': {
            'database': 'operational',
            'ai_service': 'operational' if genai_client else 'unavailable',
            'email_service': 'operational'
        }
    }), 200

# API documentation endpoint (placeholder)


@app.route('/api/v1/docs', methods=['GET'])
def api_docs():
    """API documentation"""
    return jsonify({
        'message': 'API Documentation',
        'documentation_url': 'https://docs.your-domain.com',
        'openapi_spec': '/api/v1/openapi.json',
        'postman_collection': '/api/v1/postman.json'
    }), 200


if __name__ == '__main__':
    with app.app_context():
        init_db()
        db.create_all()

    print("=" * 70)
    print("🚀 Image Manipulation API Server Starting...")
    print("=" * 70)
    print(f"📍 API Base URL: http://localhost:5000/api/v1")
    print(f"📍 Web Interface: http://localhost:5000/")
    print(f"📖 API Documentation: http://localhost:5000/api/v1/docs")
    print(f"❤️  Health Check: http://localhost:5000/api/v1/health")
    print(f"🔑 Authentication: API Key or JWT Token required")
    print(
        f"🤖 AI Service: {'✅ Available' if genai_client else '❌ Unavailable'}")
    print("=" * 70)
    print("\n💡 Quick Start:")
    print("   1. Register: POST /api/v1/auth/register")
    print("   2. Login: POST /api/v1/auth/login")
    print("   3. Create API Key: POST /api/v1/auth/api-keys")
    print("   4. Process Image: POST /api/v1/images/process")
    print("\n📚 Full documentation: See docs/API_DOCUMENTATION.md\n")
    print("=" * 70)

    app.run(host='0.0.0.0', port=5000, debug=True)
