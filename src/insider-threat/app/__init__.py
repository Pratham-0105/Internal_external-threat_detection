from flask import Flask, request, make_response, redirect, url_for
from flask_login import LoginManager, login_user, current_user
from flask_wtf import CSRFProtect
from config.config import config
import os
import json

from app.models.database import db
from app.models.database import User

login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_name='default'):
    """Application factory"""
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config[config_name])

    # CORS Support for Frontend & SOC Gateway
    @app.before_request
    def handle_cors_preflight():
        if request.method == 'OPTIONS':
            response = make_response()
            origin = request.headers.get('Origin', '*')
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key, Authorization, X-Requested-With, Accept'
            response.headers['Access-Control-Max-Age'] = '86400'
            return response

    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key, Authorization, X-Requested-With, Accept'
        return response

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    csrf.init_app(app)

    # ========================================
    # ADD CUSTOM JINJA2 FILTERS
    # ========================================
    @app.template_filter('from_json')
    def from_json_filter(value):
        """Parse JSON string to dict for template rendering"""
        try:
            return json.loads(value)
        except:
            return {}
    
    # User loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Auto-login as admin on any request to completely bypass authentication
    @app.before_request
    def auto_authenticate_user():
        if not current_user.is_authenticated:
            try:
                admin_user = User.query.filter_by(username='admin').first()
                if admin_user:
                    login_user(admin_user, remember=True)
            except Exception:
                pass

    @login_manager.unauthorized_handler
    def bypass_unauthorized():
        try:
            admin_user = User.query.filter_by(username='admin').first()
            if admin_user:
                login_user(admin_user, remember=True)
        except Exception:
            pass
        return redirect(url_for('dashboard.index'))
    
    # Register blueprints
    with app.app_context():
        from app.routes import main, auth, dashboard, api, settings, admin
        
        app.register_blueprint(main.bp)
        app.register_blueprint(auth.bp)
        app.register_blueprint(dashboard.bp)
        app.register_blueprint(api.bp)
        app.register_blueprint(settings.bp)
        app.register_blueprint(admin.bp)

        # api.bp is machine-to-machine (monitoring agents), authenticated via
        # the X-API-Key header instead of a browser session — CSRF tokens
        # don't apply to it, so it's exempted from CSRFProtect.
        csrf.exempt(api.bp)

        # Create database tables
        db.create_all()
        
        # Create default admin user if not exists
        create_default_admin()

    return app


def create_default_admin():
    """Create default admin user with a random password (printed once)."""
    from app.models.database import User
    import secrets

    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin_password = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(12)
        admin = User(
            username='admin',
            email='admin@insider-threat.local'
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        print("=" * 70)
        print("[OK] Default admin user created")
        print(f"   Username: admin")
        print(f"   Password: {admin_password}")
        print("   [NOTE] Save this now — it will not be shown again. Change it after login.")
        print("=" * 70)
