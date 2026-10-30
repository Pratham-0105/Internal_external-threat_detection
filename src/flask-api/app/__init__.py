"""
Flask application factory with CORS, SocketIO, and SQLite database support.
"""
import os
from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO
from config import Config
from app.models.db import db

socketio = SocketIO(cors_allowed_origins="*", async_mode='threading')

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # SQLite Database URI configuration
    db_path = os.path.join(app.root_path, 'nids_audit.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    CORS(app, resources={r"/*": {"origins": "*"}})
    
    db.init_app(app)
    socketio.init_app(app)

    with app.app_context():
        db.create_all()

    # Register blueprints
    from app.routes.prediction_routes import prediction_bp
    app.register_blueprint(prediction_bp)

    return app