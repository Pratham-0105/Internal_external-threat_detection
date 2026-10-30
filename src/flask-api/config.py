"""
Configuration settings for the application.
"""
import os

class Config:
    """Base configuration class."""
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    
    # Model settings
    MODEL_PATH = os.environ.get('MODEL_PATH') or 'app/models/model.pkl'
    MULTICLASS_MODEL_PATH = os.environ.get('MULTICLASS_MODEL_PATH') or 'app/models/multiclass_model.pkl'
    MULTICLASS_METADATA_PATH = os.environ.get('MULTICLASS_METADATA_PATH') or 'app/models/multiclass_metadata.json'
    
    # Network flow analysis settings
    IDLE_THRESHOLD = 500000  # Microseconds (1 second) to consider a gap as "idle"
    PREDICTION_THRESHOLD = float(os.environ.get('PREDICTION_THRESHOLD', '0.50'))  # Probability threshold to classify as an attack