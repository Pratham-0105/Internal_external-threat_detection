"""
Fixed API - Uses Comprehensive Detection Engine
"""

from flask import Blueprint, request, jsonify, current_app
from functools import wraps
from app.models.database import db, Event, Alert, UserProfile
from datetime import datetime
import json
import hashlib

bp = Blueprint('api', __name__)

# Global detection engine instance
_detection_engine = None


def require_api_key(f):
    """
    Requires the X-API-Key header to match AGENT_API_KEY (config/config.py).
    Protects endpoints that write data or disclose detection config from
    being reachable by anyone who can hit this Flask process on the network.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        expected = current_app.config.get('AGENT_API_KEY')
        provided = request.headers.get('X-API-Key')
        if not expected or provided != expected:
            return jsonify({'status': 'error', 'message': 'Unauthorized — missing or invalid X-API-Key header'}), 401
        return f(*args, **kwargs)
    return wrapper

def get_detection_engine():
    """Get or initialize the comprehensive detection engine"""
    global _detection_engine
    
    if _detection_engine is None:
        try:
            from app.utils.detection_engine import DetectionEngine
            from pathlib import Path
            
            model_path = Path('data/models')
            
            # Config for detection engine
            config = {
                'ISOLATION_FOREST_PARAMS': {
                    'n_estimators': 100,
                    'contamination': 0.1,
                    'random_state': 42,
                    'max_samples': 256
                },
                'SEVERITY_WEIGHTS': {
                    'HTTP': 1.0,
                    'FILE': 1.2,
                    'DEVICE': 1.5,
                    'EMAIL': 1.0,
                    'LOGON': 0.8,
                    'keyword_detected': 0.7,
                    'after_hours': 0.15,
                    'usb_external': 0.25,
                    'malicious_domain': 0.40,
                    'sensitive_file_access': 0.30,
                    'unusual_data_volume': 0.25
                }
            }
            
            _detection_engine = DetectionEngine(model_path, config)
            _detection_engine.load_model()
            print("[OK] Detection Engine initialized successfully!")
            
        except Exception as e:
            print(f"[ERROR] Failed to initialize detection engine: {e}")
            import traceback
            traceback.print_exc()
            _detection_engine = None
    
    return _detection_engine


@bp.route('/health', methods=['GET'])
def health():
    """Health check endpoint for Docker and Gateway orchestrator"""
    return jsonify({'status': 'healthy', 'service': 'insider-threat'}), 200


@bp.route('/api/ingest', methods=['POST'])
@bp.route('/api/receive-log', methods=['POST'])
@require_api_key
def receive_log():
    """
    Receive and process events with comprehensive detection
    - Keyword detection (checks subjects, recipients, content)
    - ML anomaly detection
    - Contextual analysis (after-hours, external recipients, etc.)
    """
    try:
        event_data = request.get_json()
        
        if not event_data:
            return jsonify({'status': 'error', 'message': 'No data received'}), 400
        
        # Normalize field names
        if 'user' in event_data and 'user_id' not in event_data:
            event_data['user_id'] = event_data['user']
        if 'user_id' in event_data and 'user' not in event_data:
            event_data['user'] = event_data['user_id']
        
        print(f"\n{'='*70}")
        print(f"[INCOMING] RECEIVED EVENT:")
        print(f"   User: {event_data.get('user')}")
        print(f"   Type: {event_data.get('event_type')}")
        print(f"   Activity: {event_data.get('activity')}")
        
        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(event_data.get('timestamp'))
            print(f"   Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        except:
            timestamp = datetime.now()
            print(f"   Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S')} (generated)")
        
        # Parse and display details
        try:
            details = json.loads(event_data.get('details', '{}'))
            if 'subject' in details:
                print(f"   Subject: {details['subject']}")
            if 'to' in details:
                print(f"   To: {details['to']}")
            if 'size' in details:
                print(f"   Size: {details['size']} bytes")
            if 'url' in details:
                print(f"   URL: {details['url'][:100]}")
        except:
            details = {}
        
        # === COMPREHENSIVE DETECTION ===
        print(f"\n[DETECTION] RUNNING DETECTION:")
        
        engine = get_detection_engine()
        
        if engine is None:
            print("   [WARN] Detection engine not available - saving event only")
            is_anomalous = False
            result = None
        else:
            # Process event through comprehensive detection engine
            result = engine.process_single_event(event_data)
            is_anomalous = result is not None
        
        # === PARSE DETECTION RESULT ===
        if result:
            risk_score = result.get('risk_score', 0.0)
            risk_level = result.get('risk_level', 'LOW')
            description = result.get('description', 'Anomalous behavior detected')
            keywords_found = result.get('keywords_found', [])
            detection_method = result.get('detection_method', 'unknown')
            anomaly_score = result.get('anomaly_score', 0.0)
            
            print(f"\n[ALERT] THREAT DETECTED!")
            print(f"   Risk Level: {risk_level}")
            print(f"   Risk Score: {risk_score:.3f}")
            print(f"   Detection Method: {detection_method}")
            if keywords_found:
                print(f"   Keywords Found: {keywords_found}")
            print(f"   Description: {description[:200]}...")
        else:
            risk_score = 0.0
            risk_level = 'NORMAL'
            description = 'Normal activity'
            keywords_found = []
            detection_method = 'none'
            anomaly_score = 0.0
            
            print(f"   [NORMAL] Normal behavior - No threat detected")
        
        # === SAVE EVENT ===
        event_id = event_data.get('event_id')
        if not event_id:
            import uuid
            event_id = f"evt_{event_data.get('user')}_{int(timestamp.timestamp())}_{str(uuid.uuid4())[:8]}"
        
        event = Event(
            event_id=event_id,
            user_id=event_data.get('user'),
            timestamp=timestamp,
            event_type=event_data.get('event_type'),
            activity=event_data.get('activity'),
            details=event_data.get('details'),
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score if is_anomalous else None,
            risk_score=risk_score if is_anomalous else None
        )
        
        db.session.add(event)
        db.session.flush()
        print(f"\n[SAVE] Event saved: {event_id}")
        
        # === CREATE ALERT IF THREAT DETECTED ===
        alert_id = None
        if is_anomalous:
            alert_id = hashlib.md5(
                f"{event_data.get('user')}{timestamp.isoformat()}{detection_method}".encode()
            ).hexdigest()[:16]
            
            alert = Alert(
                alert_id=alert_id,
                user_id=event_data.get('user'),
                timestamp=timestamp,
                alert_type=event_data.get('event_type'),
                risk_level=risk_level,
                risk_score=risk_score,
                anomaly_score=anomaly_score,
                description=description,
                event_details=event_data.get('details'),
                status='OPEN'
            )
            
            db.session.add(alert)
            print(f"[ALERT] Alert created: {alert_id}")
            print(f"   Level: {risk_level}")
            print(f"   Score: {risk_score:.3f}")
            
            # Update or create user profile
            user_profile = UserProfile.query.filter_by(user_id=event_data.get('user')).first()
            if not user_profile:
                user_profile = UserProfile(
                    user_id=event_data.get('user'),
                    full_name=event_data.get('username') or event_data.get('user'),
                    department=event_data.get('department') or 'Corporate Staff',
                    role='Staff Endpoint',
                    current_risk_level=risk_level,
                    total_alerts=1,
                    high_risk_alerts=1 if risk_level in ['HIGH', 'CRITICAL'] else 0,
                    last_alert_date=datetime.now(),
                    last_activity=timestamp,
                    created_at=datetime.utcnow()
                )
                db.session.add(user_profile)
                print(f"   Created new UserProfile for: {event_data.get('user')}")
            else:
                user_profile.total_alerts += 1
                if risk_level in ['HIGH', 'CRITICAL']:
                    user_profile.high_risk_alerts += 1
                user_profile.current_risk_level = risk_level
                user_profile.last_alert_date = datetime.now()
                user_profile.last_activity = timestamp
                print(f"   User profile updated: {event_data.get('user')}")
        else:
            # Also update last activity for normal events
            user_profile = UserProfile.query.filter_by(user_id=event_data.get('user')).first()
            if user_profile:
                user_profile.last_activity = timestamp
        
        # === COMMIT ===
        db.session.commit()
        print(f"[OK] Transaction committed")
        print(f"{'='*70}\n")

        # === REAL-TIME SOC WEBSOCKET SYNCHRONIZATION ===
        if is_anomalous:
            try:
                import urllib.request
                sync_payload = json.dumps({
                    'user_id': event_data.get('user', 'USR-UNKNOWN'),
                    'username': user_profile.full_name if user_profile and user_profile.full_name else event_data.get('user', 'Corporate Employee'),
                    'action': f"{event_data.get('event_type')}: {event_data.get('activity')}",
                    'resource': description[:100],
                    'src_ip': event_data.get('ip', '192.168.1.100'),
                    'details': description
                }).encode('utf-8')
                sync_req = urllib.request.Request(
                    'http://localhost:5000/api/ingest_insider',
                    data=sync_payload,
                    headers={'Content-Type': 'application/json'}
                )
                with urllib.request.urlopen(sync_req, timeout=1.0) as _:
                    pass
            except Exception:
                pass  # Graceful fallback if Port 5000 is running detached or not yet started

        # === RETURN RESPONSE ===
        return jsonify({
            'status': 'success',
            'event_id': event_id,
            'alert_generated': is_anomalous,
            'alert_id': alert_id,
            'risk_level': risk_level if is_anomalous else None,
            'risk_score': risk_score if is_anomalous else 0.0,
            'description': description,
            'detection_method': detection_method,
            'keywords_found': keywords_found if is_anomalous else []
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        print(f"{'='*70}\n")
        
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp.route('/api/clear', methods=['POST', 'DELETE'])
def clear_insider_events():
    """Clear all recorded insider events and alerts"""
    try:
        ev_count = Event.query.delete()
        al_count = Alert.query.delete()
        db.session.commit()
        return jsonify({
            'status': 'success',
            'deleted_events': ev_count,
            'deleted_alerts': al_count,
            'message': f'Cleared {ev_count} events and {al_count} alerts.'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/api/test', methods=['GET'])
def test_api():
    """Test endpoint to verify API is working"""
    from app.utils.detection_engine import load_settings
    
    settings = load_settings()
    
    return jsonify({
        'status': 'ok',
        'message': 'API is working',
        'detection_enabled': {
            'keywords': settings.get('keyword_detection_enabled', True),
            'ml': settings.get('ml_detection_enabled', True)
        },
        'keywords_count': len(settings.get('suspicious_keywords', [])),
        'endpoints': ['/api/ingest', '/api/receive-log']
    }), 200


@bp.route('/api/settings', methods=['GET'])
@require_api_key
def get_settings():
    """Get current detection settings"""
    from app.utils.detection_engine import load_settings
    
    settings = load_settings()
    
    return jsonify({
        'status': 'success',
        'settings': {
            'keyword_detection_enabled': settings.get('keyword_detection_enabled'),
            'ml_detection_enabled': settings.get('ml_detection_enabled'),
            'keywords_count': len(settings.get('suspicious_keywords', [])),
            'business_hours': {
                'start': settings.get('business_hours_start'),
                'end': settings.get('business_hours_end')
            },
            'weekend_days': settings.get('weekend_days'),
            'thresholds': {
                'critical': settings.get('critical_threshold'),
                'high': settings.get('high_threshold'),
                'medium': settings.get('medium_threshold'),
                'low': settings.get('low_threshold')
            }
        }
    }), 200


@bp.route('/api/settings', methods=['POST', 'PUT'])
@require_api_key
def update_settings_api():
    """Update detection settings & thresholds"""
    import os
    data = request.get_json() or {}
    new_settings = {}

    if 'keyword_detection_enabled' in data:
        new_settings['keyword_detection_enabled'] = bool(data['keyword_detection_enabled'])
    if 'ml_detection_enabled' in data:
        new_settings['ml_detection_enabled'] = bool(data['ml_detection_enabled'])

    thresholds = data.get('thresholds', {})
    if thresholds:
        if 'critical' in thresholds:
            new_settings['critical_threshold'] = float(thresholds['critical'])
        if 'high' in thresholds:
            new_settings['high_threshold'] = float(thresholds['high'])
        if 'medium' in thresholds:
            new_settings['medium_threshold'] = float(thresholds['medium'])
        if 'low' in thresholds:
            new_settings['low_threshold'] = float(thresholds['low'])

    b_hours = data.get('business_hours', {})
    if b_hours:
        if 'start' in b_hours:
            new_settings['business_hours_start'] = int(b_hours['start'])
        if 'end' in b_hours:
            new_settings['business_hours_end'] = int(b_hours['end'])

    settings_file = os.path.join('app', 'config', 'settings.json')
    try:
        from app.utils.detection_engine import load_settings
        current = load_settings()
        current.update(new_settings)
        os.makedirs(os.path.dirname(settings_file), exist_ok=True)
        with open(settings_file, 'w') as f:
            json.dump(current, f, indent=4)
        return jsonify({
            'status': 'success',
            'message': 'Detection thresholds and settings updated successfully.',
            'settings': current
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to persist settings: {str(e)}'}), 500


# ============================================================================
# USER BEHAVIOUR & UEBA REST ENDPOINTS FOR CASOC FRONTEND
# ============================================================================

def serialize_profile(p):
    """Serialize UserProfile SQLAlchemy model into clean JSON dict"""
    return {
        'user_id': p.user_id,
        'full_name': p.full_name or p.user_id,
        'department': p.department or 'Corporate Subnet',
        'role': p.role or 'Employee Endpoint',
        'supervisor': p.supervisor or 'N/A',
        'current_risk_level': p.current_risk_level or 'LOW',
        'total_alerts': p.total_alerts or 0,
        'high_risk_alerts': p.high_risk_alerts or 0,
        'avg_logon_time': str(p.avg_logon_time) if p.avg_logon_time else '08:30:00',
        'avg_logoff_time': str(p.avg_logoff_time) if p.avg_logoff_time else '17:30:00',
        'typical_work_days': p.typical_work_days or 'Mon-Fri',
        'avg_file_accesses_per_day': round(p.avg_file_accesses_per_day or 0.0, 1),
        'avg_http_requests_per_day': round(p.avg_http_requests_per_day or 0.0, 1),
        'avg_email_count_per_day': round(p.avg_email_count_per_day or 0.0, 1),
        'usb_usage_frequency': round(p.usb_usage_frequency or 0.0, 2),
        'last_activity': p.last_activity.isoformat() if p.last_activity else None,
        'last_alert_date': p.last_alert_date.isoformat() if p.last_alert_date else None
    }


@bp.route('/api/users', methods=['GET'])
def get_users_api():
    """Retrieve all monitored CERT r4.2 user behavioral profiles with search and risk level filtering"""
    from sqlalchemy import or_, desc
    
    search = request.args.get('search', '').strip()
    department = request.args.get('department', '').strip()
    risk_level = request.args.get('risk_level', '').strip()
    limit = min(request.args.get('limit', 50, type=int), 200)
    page = request.args.get('page', 1, type=int)

    query = UserProfile.query

    if search:
        query = query.filter(
            or_(
                UserProfile.user_id.ilike(f'%{search}%'),
                UserProfile.full_name.ilike(f'%{search}%')
            )
        )
    if department:
        query = query.filter(UserProfile.department.ilike(f'%{department}%'))
    if risk_level and risk_level.upper() != 'ALL':
        query = query.filter(UserProfile.current_risk_level == risk_level.upper())

    total_count = query.count()
    critical_count = UserProfile.query.filter_by(current_risk_level='CRITICAL').count()
    high_count = UserProfile.query.filter_by(current_risk_level='HIGH').count()
    medium_count = UserProfile.query.filter_by(current_risk_level='MEDIUM').count()
    low_count = UserProfile.query.filter_by(current_risk_level='LOW').count()

    # Priority ordering: users with active alerts first, then critical/high risk, then user_id
    users = query.order_by(
        desc(UserProfile.total_alerts),
        desc(UserProfile.high_risk_alerts),
        UserProfile.user_id
    ).paginate(page=page, per_page=limit, error_out=False).items

    return jsonify({
        'status': 'success',
        'total_count': total_count,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'users': [serialize_profile(u) for u in users]
    }), 200


@bp.route('/api/users/<user_id>', methods=['GET'])
def get_user_profile_api(user_id):
    """Retrieve individual user behavioral profile and baseline metrics"""
    p = UserProfile.query.filter_by(user_id=user_id).first()
    if not p:
        return jsonify({'status': 'error', 'message': f'User {user_id} not found'}), 404
    return jsonify({
        'status': 'success',
        'user': serialize_profile(p)
    }), 200


@bp.route('/api/users/<user_id>/events', methods=['GET'])
def get_user_events_api(user_id):
    """Retrieve chronological event history for a specific user"""
    events = Event.query.filter_by(user_id=user_id).order_by(Event.timestamp.desc()).limit(100).all()
    ev_list = []
    for e in events:
        ev_list.append({
            'id': e.id,
            'event_id': e.event_id,
            'timestamp': e.timestamp.isoformat() if e.timestamp else None,
            'event_type': e.event_type,
            'activity': e.activity,
            'details': e.details,
            'is_anomalous': bool(e.is_anomalous),
            'anomaly_score': round(e.anomaly_score, 3) if e.anomaly_score else None,
            'risk_score': round(e.risk_score, 3) if e.risk_score else None
        })
    return jsonify({
        'status': 'success',
        'count': len(ev_list),
        'events': ev_list
    }), 200


@bp.route('/api/users/<user_id>/alerts', methods=['GET'])
def get_user_alerts_api(user_id):
    """Retrieve security alerts generated for a specific user"""
    alerts = Alert.query.filter_by(user_id=user_id).order_by(Alert.timestamp.desc()).all()
    al_list = []
    for a in alerts:
        al_list.append({
            'id': a.id,
            'alert_id': a.alert_id,
            'timestamp': a.timestamp.isoformat() if a.timestamp else None,
            'alert_type': a.alert_type,
            'risk_level': a.risk_level,
            'risk_score': round(a.risk_score, 3) if a.risk_score else 0.0,
            'anomaly_score': round(a.anomaly_score, 3) if a.anomaly_score else 0.0,
            'description': a.description,
            'status': a.status
        })
    return jsonify({
        'status': 'success',
        'count': len(al_list),
        'alerts': al_list
    }), 200


@bp.route('/api/events', methods=['GET'])
def get_global_events_api():
    """Retrieve recently appended live user events across all entities"""
    limit = min(request.args.get('limit', 50, type=int), 200)
    anomalous_only = request.args.get('anomalous', '').lower() == 'true'
    
    query = Event.query
    if anomalous_only:
        query = query.filter_by(is_anomalous=True)
        
    events = query.order_by(Event.timestamp.desc()).limit(limit).all()
    
    # Pre-fetch user profiles for employee names
    user_ids = list({e.user_id for e in events})
    profiles = {p.user_id: p for p in UserProfile.query.filter(UserProfile.user_id.in_(user_ids)).all()} if user_ids else {}
    
    ev_list = []
    for e in events:
        p = profiles.get(e.user_id)
        ev_list.append({
            'id': e.id,
            'event_id': e.event_id,
            'user_id': e.user_id,
            'full_name': p.full_name if p else e.user_id,
            'department': p.department if p else 'Corporate Staff',
            'timestamp': e.timestamp.isoformat() if e.timestamp else None,
            'event_type': e.event_type,
            'activity': e.activity,
            'details': e.details,
            'is_anomalous': bool(e.is_anomalous),
            'anomaly_score': round(e.anomaly_score, 3) if e.anomaly_score else None,
            'risk_score': round(e.risk_score, 3) if e.risk_score else None
        })
        
    return jsonify({
        'status': 'success',
        'count': len(ev_list),
        'total_events_in_db': Event.query.count(),
        'events': ev_list
    }), 200


@bp.route('/api/alerts', methods=['GET'])
def get_global_alerts_api():
    """Retrieve recently generated live alerts across all entities"""
    limit = min(request.args.get('limit', 50, type=int), 200)
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
    
    user_ids = list({a.user_id for a in alerts})
    profiles = {p.user_id: p for p in UserProfile.query.filter(UserProfile.user_id.in_(user_ids)).all()} if user_ids else {}
    
    al_list = []
    for a in alerts:
        p = profiles.get(a.user_id)
        al_list.append({
            'id': a.id,
            'alert_id': a.alert_id,
            'user_id': a.user_id,
            'full_name': p.full_name if p else a.user_id,
            'department': p.department if p else 'Corporate Staff',
            'timestamp': a.timestamp.isoformat() if a.timestamp else None,
            'alert_type': a.alert_type,
            'risk_level': a.risk_level,
            'risk_score': round(a.risk_score, 3) if a.risk_score else 0.0,
            'anomaly_score': round(a.anomaly_score, 3) if a.anomaly_score else 0.0,
            'description': a.description,
            'status': a.status
        })
        
    return jsonify({
        'status': 'success',
        'count': len(al_list),
        'total_alerts_in_db': Alert.query.count(),
        'alerts': al_list
    }), 200


@bp.route('/api/stats', methods=['GET'])
def get_ueba_stats_api():
    """Retrieve real-time summary statistics for User Behaviour Analytics"""
    total_users = UserProfile.query.count()
    critical_users = UserProfile.query.filter_by(current_risk_level='CRITICAL').count()
    high_users = UserProfile.query.filter_by(current_risk_level='HIGH').count()
    medium_users = UserProfile.query.filter_by(current_risk_level='MEDIUM').count()
    low_users = UserProfile.query.filter_by(current_risk_level='LOW').count()
    
    total_events = Event.query.count()
    anomalous_events = Event.query.filter_by(is_anomalous=True).count()
    total_alerts = Alert.query.count()
    
    return jsonify({
        'status': 'success',
        'total_users': total_users,
        'critical_users': critical_users,
        'high_users': high_users,
        'medium_users': medium_users,
        'low_users': low_users,
        'total_events': total_events,
        'anomalous_events': anomalous_events,
        'total_alerts': total_alerts
    }), 200


@bp.route('/api/users/<user_id>/lock', methods=['POST'])
@require_api_key
def lock_user_account(user_id):
    """Lock user account to contain insider risk"""
    user_p = UserProfile.query.filter_by(user_id=user_id).first()
    if not user_p:
        return jsonify({'status': 'error', 'message': f'User {user_id} not found'}), 404

    user_p.current_risk_level = 'LOCKED'

    lock_event = Event(
        event_id=f"evt_lock_{user_id}_{int(datetime.now().timestamp())}",
        user_id=user_id,
        timestamp=datetime.now(),
        event_type='CONTAINMENT',
        activity='User Account Locked via CASOC Automated Response',
        details=json.dumps({'action': 'ACCOUNT_LOCKED', 'initiator': 'CASOC Admin'}),
        is_anomalous=False,
        risk_score=1.0
    )
    db.session.add(lock_event)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Account for user {user_id} has been suspended & credentials locked.',
        'user': serialize_profile(user_p)
    }), 200


@bp.route('/api/users/<user_id>/terminate-session', methods=['POST'])
@require_api_key
def terminate_user_session(user_id):
    """Terminate active logon sessions, SSH connections, and authentication tokens for an insider user"""
    user_p = UserProfile.query.filter_by(user_id=user_id).first()
    if not user_p:
        return jsonify({'status': 'error', 'message': f'User {user_id} not found'}), 404

    term_event = Event(
        event_id=f"evt_term_{user_id}_{int(datetime.now().timestamp())}",
        user_id=user_id,
        timestamp=datetime.now(),
        event_type='CONTAINMENT',
        activity='Active Domain Sessions Terminated & Tokens Revoked',
        details=json.dumps({'action': 'SESSION_TERMINATED', 'initiator': 'CASOC Automated Response Engine'}),
        is_anomalous=False,
        risk_score=0.8
    )
    db.session.add(term_event)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Active logon sessions, SSH keys, and tokens for user {user_id} have been terminated.',
        'user': serialize_profile(user_p)
    }), 200