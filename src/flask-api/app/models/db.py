"""
Database persistence engine for logging network intrusion events and analyst triage actions.
Uses SQLite via SQLAlchemy for low-overhead embedded storage.
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class IncidentRecord(db.Model):
    __tablename__ = 'incident_records'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), default=lambda: datetime.now().isoformat())
    time_display = db.Column(db.String(20), default=lambda: datetime.now().strftime("%H:%M:%S"))
    vector = db.Column(db.String(100), nullable=False)
    src_ip = db.Column(db.String(50), nullable=False)
    dst_ip = db.Column(db.String(50), nullable=False)
    is_attack = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Float, default=0.0)
    prediction_code = db.Column(db.Integer, default=0)
    latency_ms = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(30), default='NEW')  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    action_taken = db.Column(db.String(200), default='None')
    notes = db.Column(db.Text, default='')
    features_json = db.Column(db.Text, default='{}')

    def to_dict(self):
        vec_lower = (self.vector or '').lower()
        dst_lower = (self.dst_ip or '').lower()
        is_insider = 'insider' in vec_lower or 'usr-' in dst_lower or 'dev.engineer' in dst_lower or 'internal.analyst' in dst_lower
        category = 'Insider Threat' if is_insider else ('External Threat' if self.is_attack else 'Normal Traffic')
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'time_display': self.time_display,
            'vector': self.vector,
            'category': category,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'is_attack': self.is_attack,
            'confidence': round(self.confidence * 100, 2) if self.confidence else 0.0,
            'prediction': self.prediction_code,
            'latency': self.latency_ms,
            'status': self.status,
            'action_taken': self.action_taken,
            'notes': self.notes
        }
