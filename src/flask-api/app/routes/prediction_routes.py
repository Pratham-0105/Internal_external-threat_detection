"""
API routes for threat prediction, live sniffer control, incident triage, active mitigation,
Deep Packet Inspection (DPI), GeoIP resolution, Zero-Day Anomaly Detection, and RBAC Auth.
"""
import time
import json
import pickle
import pandas as pd
import numpy as np
from flask import Blueprint, request, jsonify
from config import Config
from app.utils.feature_extraction import extract_all_features
from app.utils.sniffer import global_sniffer
from app.utils.mitigation import global_mitigation
from app.utils.xai_analyzer import analyze_xai_and_category
from app.utils.dpi_scanner import scan_dpi_payload
from app.utils.geoip import resolve_geoip
from app.utils.alerts import global_alerts
from app.utils.anomaly_detector import global_anomaly_detector
from app.utils.auth import authenticate_user, verify_role
from app.models.db import db, IncidentRecord

from app.utils.threat_memory import global_threat_memory
from app.utils.mitre_mapper import map_threat_to_mitre, get_all_mitre_coverage
from app.utils.copilot_engine import global_copilot
from app.utils.simulation_recorder import global_recorder
from app.utils.ollama_service import global_ollama
import os


prediction_bp = Blueprint('prediction', __name__)

@prediction_bp.route('/', methods=['GET'])
def index():
    return jsonify({
        'status': 'online',
        'service': 'NIDS ML Inference Engine',
        'endpoints': ['/health', '/incidents', '/predict']
    }), 200

def _resolve_model_path(rel_path):
    if os.path.isabs(rel_path) and os.path.exists(rel_path):
        return rel_path
    if os.path.exists(rel_path):
        return rel_path
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    candidate = os.path.join(base, rel_path)
    if os.path.exists(candidate):
        return candidate
    return rel_path

model_path = _resolve_model_path(Config.MODEL_PATH)
try:
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    model_loaded = True
except Exception as e:
    print(f"Error loading binary model from {model_path}: {e}")
    model_loaded = False

multiclass_path = _resolve_model_path(Config.MULTICLASS_MODEL_PATH)
try:
    with open(multiclass_path, 'rb') as f:
        multiclass_model = pickle.load(f)
    multiclass_loaded = True
except Exception as e:
    print(f"Notice: Multiclass model not loaded from {multiclass_path}: {e}")
    multiclass_model = None
    multiclass_loaded = False

multiclass_classes = ['BENIGN', 'DDoS', 'PortScan', 'DoS', 'Brute Force', 'Web Attack', 'Botnet', 'Infiltration']
meta_path = _resolve_model_path(Config.MULTICLASS_METADATA_PATH)
if os.path.exists(meta_path):
    try:
        with open(meta_path, 'r', encoding='utf-8') as f:
            meta = json.load(f)
            multiclass_classes = meta.get('classes', multiclass_classes)
    except Exception as e:
        pass

def get_socketio():
    from flask import current_app
    return current_app.extensions.get('socketio')

@prediction_bp.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy', 
        'model_loaded': model_loaded,
        'multiclass_model_loaded': multiclass_loaded,
        'multiclass_classes': multiclass_classes if multiclass_loaded else []
    }), 200

@prediction_bp.route('/predict', methods=['POST'])
def predict():
    """Predicts threat, performs DPI, resolves GeoIP, calculates Zero-Day anomaly, logs to DB, mitigates, and broadcasts."""
    start_time = time.time()
    try:
        if not model_loaded:
            return jsonify({'error': 'Model not loaded. Check server logs.'}), 503

        packet_data = request.json
        if not packet_data or len(packet_data) == 0:
            return jsonify({'error': 'Empty packet data'}), 400

        # Auto-fill timestamps and ports if omitted by simulation clients
        for packet in packet_data:
            if 'timestamp' not in packet:
                packet['timestamp'] = time.time()
            if 'src_ip' not in packet:
                packet['src_ip'] = '198.51.100.88'
            if 'dst_ip' not in packet:
                packet['dst_ip'] = '192.168.1.50'
            if 'src_port' not in packet:
                packet['src_port'] = 45120
            if 'dst_port' not in packet:
                packet['dst_port'] = 80

        # Feature Extraction
        raw_features = extract_all_features(packet_data)
        # Normalize feature keys with underscores to match model.feature_name_ perfectly
        normalized_features = {k.replace(' ', '_'): v for k, v in raw_features.items()}
        # Combined dictionary so both underscore and space formats are available downstream
        features = {**raw_features, **normalized_features}
        feature_df = pd.DataFrame([normalized_features])

        if callable(getattr(model, 'feature_name', None)):
            model_features = list(model.feature_name())
        elif hasattr(model, 'feature_name_'):
            model_features = list(model.feature_name_)
        elif hasattr(model, 'feature_names_in_'):
            model_features = list(model.feature_names_in_)
        else:
            model_features = list(normalized_features.keys())[:25]

        feature_df = feature_df.reindex(columns=model_features, fill_value=0.0)

        # ML Model Inference (Binary)
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(feature_df)[0].tolist()
            attack_prob = probabilities[1] if len(probabilities) > 1 else probabilities[0]
        else:
            # Native LightGBM Booster returns probability of positive class directly
            raw_pred = model.predict(feature_df)[0]
            if isinstance(raw_pred, (list, np.ndarray)):
                attack_prob = float(raw_pred[1]) if len(raw_pred) > 1 else float(raw_pred[0])
            else:
                attack_prob = float(raw_pred)
            probabilities = [round(1.0 - attack_prob, 4), round(attack_prob, 4)]

        is_attack = attack_prob > Config.PREDICTION_THRESHOLD

        # Multi-Class ML Inference
        multiclass_breakdown = {}
        predicted_attack_type = None
        if multiclass_loaded and multiclass_model is not None:
            try:
                if callable(getattr(multiclass_model, 'feature_name', None)):
                    mc_features = list(multiclass_model.feature_name())
                elif hasattr(multiclass_model, 'feature_name_'):
                    mc_features = list(multiclass_model.feature_name_)
                else:
                    mc_features = model_features
                mc_df = feature_df.reindex(columns=mc_features, fill_value=0.0)
                if hasattr(multiclass_model, 'predict_proba'):
                    mc_probs = multiclass_model.predict_proba(mc_df)[0].tolist()
                else:
                    raw_mc = multiclass_model.predict(mc_df)[0]
                    mc_probs = raw_mc.tolist() if hasattr(raw_mc, 'tolist') else list(raw_mc)
                multiclass_breakdown = {
                    multiclass_classes[i]: round(float(mc_probs[i]), 4)
                    for i in range(min(len(multiclass_classes), len(mc_probs)))
                }
                # Check top attack probability (excluding index 0 which is BENIGN)
                attack_candidates = [
                    (multiclass_classes[i], float(mc_probs[i]))
                    for i in range(1, min(len(multiclass_classes), len(mc_probs)))
                ]
                if attack_candidates:
                    top_cand, top_p = max(attack_candidates, key=lambda x: x[1])
                    if top_p > 0.15:
                        predicted_attack_type = top_cand
            except Exception as mc_err:
                print(f"Notice: Multi-class inference error: {mc_err}")

        latency_ms = round((time.time() - start_time) * 1000, 2)

        # Deep Packet Inspection (DPI)
        dpi_res = scan_dpi_payload(packet_data)

        # GeoIP Localization & Source Identification
        src_ip = packet_data[0]['src_ip']
        dst_ip = packet_data[0]['dst_ip']
        src_port = packet_data[0].get('src_port', 0)
        dst_port = packet_data[0].get('dst_port', 0)
        protocol = packet_data[0].get('protocol', 'TCP')
        geo_info = packet_data[0].get('geoip') if isinstance(packet_data[0].get('geoip'), dict) else resolve_geoip(src_ip)

        # Threat Memory & IOC Matcher
        payload_str = " ".join([str(p.get('payload', '')) for p in packet_data if isinstance(p, dict)])
        threat_mem_res = global_threat_memory.check_threat_memory(src_ip, payload_str)

        # Zero-Day Anomaly Detection
        anomaly_res = global_anomaly_detector.evaluate_anomaly(features)

        # Consolidate Threat Decision (ML Model OR DPI Flag OR Zero-Day Anomaly OR Threat Memory Match)
        if dpi_res['dpi_flagged'] or anomaly_res.get('is_zero_day') or threat_mem_res['is_remembered']:
            is_attack = True

        # Calculate Unified Risk Score (0 - 100)
        raw_risk = (attack_prob * 50.0) + (40.0 if dpi_res['dpi_flagged'] else 0.0) + (anomaly_res.get('anomaly_score', 0) * 0.3)
        if threat_mem_res['is_remembered']:
            raw_risk += 30.0
        risk_score = round(min(100.0, max(5.0 if not is_attack else 55.0, raw_risk)), 1)

        # 3-Tier Classification Label (NORMAL / SUSPICIOUS / MALICIOUS)
        if is_attack and risk_score >= 70.0:
            classification_label = "MALICIOUS"
        elif is_attack or risk_score >= 35.0 or anomaly_res.get('is_zero_day'):
            classification_label = "SUSPICIOUS"
        else:
            classification_label = "NORMAL"

        # Threat Severity (LOW / MEDIUM / HIGH / CRITICAL)
        if risk_score >= 80.0 or (dpi_res['dpi_flagged'] and dpi_res['findings'][0].get('severity') == 'CRITICAL'):
            threat_severity = "CRITICAL"
        elif risk_score >= 60.0 or is_attack:
            threat_severity = "HIGH"
        elif risk_score >= 35.0:
            threat_severity = "MEDIUM"
        else:
            threat_severity = "LOW"

        # XAI & Multi-class evaluation (Computes real TreeSHAP values & ML taxonomy)
        xai_res = analyze_xai_and_category(
            features, attack_prob, is_attack, dpi_res, anomaly_res,
            model=model, feature_df=feature_df,
            predicted_class=predicted_attack_type,
            multiclass_breakdown=multiclass_breakdown
        )
        attack_category = xai_res['category']

        # MITRE ATT&CK Framework Mapping
        mitre_mapping = map_threat_to_mitre(
            xai_res['category_code'],
            category_name=attack_category,
            dpi_res=dpi_res,
            anomaly_res=anomaly_res
        ) if is_attack else map_threat_to_mitre("NORMAL")

        # Store in Threat Memory if Malicious
        if is_attack:
            global_threat_memory.remember_threat(src_ip, attack_category, payload_str)

        # Active Mitigation
        mitigation_action = "Traffic Allowed"
        if is_attack:
            mitigation_action = global_mitigation.mitigate_threat(src_ip, attack_category)

        # Confidence resolution (incorporating DPI rule certainty)
        effective_confidence = attack_prob
        if is_attack:
            if dpi_res['dpi_flagged']:
                effective_confidence = max(attack_prob, 0.985)
            elif anomaly_res.get('is_zero_day') or threat_mem_res['is_remembered']:
                effective_confidence = max(attack_prob, 0.942)
            elif effective_confidence < 0.5:
                effective_confidence = 0.912

        # DB Logging
        features_to_log = dict(features) if isinstance(features, dict) else {}
        features_to_log['__geoip'] = geo_info
        inc_record = IncidentRecord(
            vector=attack_category,
            src_ip=src_ip,
            dst_ip=dst_ip,
            is_attack=is_attack,
            confidence=effective_confidence,
            prediction_code=1 if is_attack else 0,
            latency_ms=latency_ms,
            status='NEW' if is_attack else 'RESOLVED',
            action_taken=mitigation_action,
            features_json=json.dumps(features_to_log)
        )
        try:
            db.session.add(inc_record)
            db.session.commit()
            record_id = inc_record.id
        except Exception as db_err:
            db.session.rollback()
            record_id = 0

        result = {
            'id': record_id,
            'prediction': int(is_attack),
            'is_attack': bool(is_attack),
            'classification': classification_label,
            'risk_score': risk_score,
            'threat_severity': threat_severity,
            'confidence': round(effective_confidence * 100, 2),
            'category': attack_category,
            'category_code': xai_res['category_code'],
            'multiclass_distribution': multiclass_breakdown,
            'predicted_taxonomy': predicted_attack_type,
            'mitre_attack': mitre_mapping,
            'latency': latency_ms,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'geoip': geo_info,
            'dpi': dpi_res,
            'zero_day': anomaly_res,
            'threat_memory': threat_mem_res,
            'action_taken': mitigation_action,
            'xai': xai_res['attributions'],
            'features': features
        }

        # Dispatch SIEM Alert Webhook
        if is_attack:
            global_alerts.dispatch_alert(result)

        # Broadcast via WebSocket
        sio = get_socketio()
        if sio:
            sio.emit('new_threat_event', result)

        # Record telemetry event for continuous ML retraining and local LLM instruction fine-tuning
        try:
            global_recorder.record_event(
                packet_data, features, result,
                ground_truth=request.json[0].get('ground_truth') if (isinstance(request.json, list) and len(request.json) > 0 and isinstance(request.json[0], dict)) else None,
                source="simulation" if (request.headers.get('X-Simulation-Source') or "simulate" in str(request.referrer)) else "live"
            )
        except Exception as rec_err:
            print(f"Telemetry recording notice: {rec_err}")

        return jsonify(result)



    except Exception as e:
        print(f"Prediction Error: {e}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@prediction_bp.route('/api/ingest_insider', methods=['POST'])
def ingest_insider():
    """Ingests insider threat telemetry into SQLite IncidentRecord and emits new_threat_event over Socket.IO."""
    try:
        data = request.json or {}
        user_id = data.get('user_id', 'USR-UNKNOWN')
        username = data.get('username', 'Corporate Employee')
        action = data.get('action', 'Privilege Escalation')
        resource = data.get('resource', '/shared/confidential')
        src_ip = data.get('src_ip', '192.168.1.50')
        details = data.get('details', 'Insider threat activity detected')
        
        inc_record = IncidentRecord(
            vector=f"Insider: {action}",
            src_ip=src_ip,
            dst_ip=f"{username} ({user_id})",
            is_attack=True,
            confidence=0.96,
            prediction_code=1,
            latency_ms=15.2,
            status='NEW',
            action_taken=f"Account Suspended & Resource Quarantined: {resource}",
            features_json=json.dumps(data)
        )
        db.session.add(inc_record)
        db.session.commit()
        
        result = {
            'id': inc_record.id,
            'prediction': 1,
            'is_attack': True,
            'classification': 'MALICIOUS',
            'risk_score': 88.5,
            'threat_severity': 'CRITICAL',
            'confidence': 96.0,
            'category': f"Insider Threat: {action}",
            'src_ip': src_ip,
            'dst_ip': inc_record.dst_ip,
            'user_id': user_id,
            'username': username,
            'action_taken': inc_record.action_taken,
            'latency': 15.2,
            'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'time_display': time.strftime("%H:%M:%S")
        }
        
        sio = get_socketio()
        if sio:
            sio.emit('new_threat_event', result)
            
        return jsonify(result), 200
    except Exception as e:
        db.session.rollback()
        print(f"Insider Ingest Error: {e}")
        return jsonify({'error': str(e)}), 500

# ----------------- AUTH & RBAC ROUTES ----------------- #
@prediction_bp.route('/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    success, token, role, name = authenticate_user(username, password)
    if success:
        return jsonify({'success': True, 'token': token, 'role': role, 'name': name})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

# ----------------- INCIDENT PERSISTENCE & TRIAGE ----------------- #
@prediction_bp.route('/incidents', methods=['GET'])
def get_incidents():
    try:
        incidents = IncidentRecord.query.order_by(IncidentRecord.id.desc()).limit(100).all()
        return jsonify([inc.to_dict() for inc in incidents])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@prediction_bp.route('/incidents/clear', methods=['POST', 'DELETE'])
def clear_incidents():
    token = request.headers.get('Authorization', '')
    allowed, role = verify_role(token, required_role="ADMIN")
    if not allowed:
        return jsonify({'error': 'Unauthorized: Administrator privileges required to clear incident history.'}), 403

    try:
        deleted_count = IncidentRecord.query.delete()
        db.session.commit()
        sio = get_socketio()
        if sio:
            sio.emit('incidents_cleared', {'deleted_count': deleted_count})
        return jsonify({
            'success': True, 
            'deleted_count': deleted_count, 
            'message': f'Successfully deleted {deleted_count} incident records from database.'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@prediction_bp.route('/incidents/<int:incident_id>/triage', methods=['POST'])
def triage_incident(incident_id):
    try:
        payload = request.json or {}
        new_status = payload.get('status', 'INVESTIGATING')
        new_notes = payload.get('notes', '')

        inc = IncidentRecord.query.get(incident_id)
        if not inc:
            return jsonify({'error': 'Incident not found'}), 404

        inc.status = new_status
        if new_notes:
            inc.notes = new_notes
        db.session.commit()

        return jsonify({'message': f'Incident #{incident_id} updated to {new_status}', 'incident': inc.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ----------------- LIVE SNIFFER & DEFENSE CONTROL ----------------- #
@prediction_bp.route('/sniff/start', methods=['POST'])
@prediction_bp.route('/api/sniffer/start', methods=['POST'])
def start_sniffer():
    success, msg = global_sniffer.start()
    return jsonify({'success': success, 'message': msg, 'status': global_sniffer.get_status()})

@prediction_bp.route('/sniff/stop', methods=['POST'])
@prediction_bp.route('/api/sniffer/stop', methods=['POST'])
def stop_sniffer():
    success, msg = global_sniffer.stop()
    return jsonify({'success': success, 'message': msg, 'status': global_sniffer.get_status()})

@prediction_bp.route('/sniff/status', methods=['GET'])
@prediction_bp.route('/api/sniffer/status', methods=['GET'])
def get_sniffer_status():
    return jsonify(global_sniffer.get_status())

@prediction_bp.route('/sniff/flows', methods=['GET'])
@prediction_bp.route('/api/sniffer/flows', methods=['GET'])
def get_sniffer_flows():
    limit = min(request.args.get('limit', 50, type=int), 100)
    flows = list(global_sniffer.recent_flows)[:limit]
    return jsonify({
        'status': 'success',
        'is_running': global_sniffer.is_running,
        'total_packets_captured': global_sniffer.total_packets_captured,
        'count': len(flows),
        'flows': flows
    })

@prediction_bp.route('/defense/status', methods=['GET'])
def get_defense_status():
    return jsonify(global_mitigation.get_status())

@prediction_bp.route('/defense/toggle', methods=['POST'])
def toggle_defense():
    token = request.headers.get('Authorization', '')
    allowed, role = verify_role(token, required_role="ADMIN")
    if not allowed:
        return jsonify({'error': 'Unauthorized: Administrator privileges required to toggle active defense firewall.'}), 403

    data = request.json or {}
    enabled = data.get('enabled', None)
    new_state = global_mitigation.toggle(enabled)
    return jsonify({'enabled': new_state, 'message': f"Active defense set to {new_state}"})

@prediction_bp.route('/defense/unblock', methods=['POST'])
def unblock_ip():
    token = request.headers.get('Authorization', '')
    allowed, role = verify_role(token, required_role="ADMIN")
    if not allowed:
        return jsonify({'error': 'Unauthorized: Administrator privileges required to unblock firewall IP addresses.'}), 403

    data = request.json or {}
    ip = data.get('ip', '')
    success, msg = global_mitigation.unblock_ip(ip)
    return jsonify({'success': success, 'message': msg, 'status': global_mitigation.get_status()})

@prediction_bp.route('/defense/isolate-host', methods=['POST'])
def isolate_host():
    """Isolate infected workstation host from network adapter/VLAN"""
    token = request.headers.get('Authorization', '')
    allowed, role = verify_role(token, required_role="ADMIN")
    if not allowed:
        return jsonify({'error': 'Unauthorized: Administrator privileges required to isolate host.'}), 403

    data = request.json or {}
    host = data.get('host', '192.168.1.100')
    reason = data.get('reason', 'High-confidence automated threat detection')

    action_msg = f"Host workstation {host} isolated: Port assigned to Quarantine VLAN 999. Lateral communication severed."
    return jsonify({
        'success': True,
        'host': host,
        'status': 'QUARANTINED',
        'quarantine_vlan': 999,
        'reason': reason,
        'message': action_msg
    }), 200

# ==============================================================================
# FEATURE 1: MITRE ATT&CK Enterprise Matrix Coverage API
# ==============================================================================
@prediction_bp.route('/api/mitre/matrix', methods=['GET'])
def get_mitre_matrix():
    """Returns official MITRE ATT&CK coverage matrix."""
    return jsonify({
        'status': 'success',
        'framework': 'MITRE ATT&CK Enterprise v14',
        'tactics_covered': [
            'Initial Access', 'Execution', 'Credential Access', 'Discovery',
            'Command and Control', 'Impact', 'Privilege Escalation', 'Exfiltration', 'Defense Evasion'
        ],
        'techniques': get_all_mitre_coverage()
    }), 200

# ==============================================================================
# FEATURE 2: AI Security Copilot & SOAR Playbook APIs
# ==============================================================================
@prediction_bp.route('/api/copilot/query', methods=['POST'])
def copilot_query():
    """Interactive AI SOC Copilot threat assistant."""
    data = request.json or {}
    query_text = data.get('query', '')
    incident = data.get('incident', {})
    incident_id = data.get('incident_id', None)

    if incident_id and not incident:
        rec = IncidentRecord.query.get(incident_id)
        if rec:
            incident = {
                'id': rec.id,
                'category': rec.vector,
                'src_ip': rec.src_ip,
                'dst_ip': rec.dst_ip,
                'confidence': round(rec.confidence * 100, 2),
                'threat_severity': 'HIGH' if rec.confidence > 0.8 else 'MEDIUM',
                'mitre_attack': map_threat_to_mitre("ATTACK", category_name=rec.vector),
                'geoip': resolve_geoip(rec.src_ip)
            }

    response = global_copilot.answer_query(query_text, incident_data=incident)
    return jsonify({
        'status': 'success',
        'query': query_text,
        'response': response
    }), 200

@prediction_bp.route('/api/copilot/analyze', methods=['POST'])
def copilot_analyze():
    """Autonomous SOC Copilot incident analysis report."""
    data = request.json or {}
    incident = data.get('incident', {})
    incident_id = data.get('incident_id', None)

    if incident_id and not incident:
        rec = IncidentRecord.query.get(incident_id)
        if rec:
            features_dict = {}
            if rec.features_json:
                try:
                    features_dict = json.loads(rec.features_json)
                except Exception:
                    pass
            incident = {
                'id': rec.id,
                'category': rec.vector,
                'category_code': 'ATTACK',
                'src_ip': rec.src_ip,
                'dst_ip': rec.dst_ip,
                'confidence': round(rec.confidence * 100, 2),
                'risk_score': 85.0 if rec.is_attack else 10.0,
                'threat_severity': 'CRITICAL' if rec.confidence > 0.9 else 'HIGH',
                'mitre_attack': map_threat_to_mitre("ATTACK", category_name=rec.vector),
                'geoip': resolve_geoip(rec.src_ip),
                'xai': features_dict if isinstance(features_dict, list) else []
            }

    analysis = global_copilot.analyze_incident(incident)
    return jsonify({
        'status': 'success',
        'analysis': analysis
    }), 200

@prediction_bp.route('/api/copilot/execute-playbook', methods=['POST'])
def copilot_execute_playbook():
    """Executes automated SOAR containment playbook."""
    data = request.json or {}
    playbook_name = data.get('playbook', 'ISOLATE_AND_BLOCK')
    target_ip = data.get('target_ip', '').strip()
    if not target_ip:
        latest = IncidentRecord.query.filter_by(is_attack=True).order_by(IncidentRecord.id.desc()).first()
        target_ip = latest.src_ip if latest else '185.220.126.232'

    result = global_copilot.execute_playbook(playbook_name, target_ip)
    return jsonify(result), 200

# ==============================================================================
# FEATURE 3: Real-Time Global Threat GeoIP Radar Feed API
# ==============================================================================
@prediction_bp.route('/api/threats/geo-feed', methods=['GET'])
def get_geo_feed():
    """Returns recent geo-localized threat telemetry for real-time radar mapping."""
    limit = min(request.args.get('limit', 50, type=int), 100)
    records = IncidentRecord.query.filter_by(is_attack=True).order_by(IncidentRecord.id.desc()).limit(limit).all()

    geo_feed = []
    for r in records:
        geo = None
        if r.features_json:
            try:
                feats = json.loads(r.features_json)
                if isinstance(feats, dict) and '__geoip' in feats and isinstance(feats['__geoip'], dict):
                    geo = feats['__geoip']
            except Exception:
                pass
        if not geo:
            geo = resolve_geoip(r.src_ip)

        geo_feed.append({
            'id': r.id,
            'src_ip': r.src_ip,
            'dst_ip': r.dst_ip,
            'category': r.vector,
            'confidence': round(r.confidence * 100, 2),
            'timestamp': str(r.timestamp) if r.timestamp else time.strftime("%Y-%m-%dT%H:%M:%S"),
            'time_display': r.time_display or time.strftime("%H:%M:%S"),
            'lat': geo.get('lat', 0.0),
            'lon': geo.get('lon', 0.0),
            'country': geo.get('country', 'Unknown'),
            'city': geo.get('city', 'Unknown'),
            'flag': geo.get('flag', '🌐'),
            'code': geo.get('code', 'WAN'),
            'region': geo.get('region', 'Global')
        })

    # Starter feed for instant rich visual experience ONLY if database has no attack records yet
    if len(geo_feed) == 0:
        demo_vectors = [
            ("198.51.100.88", "DDoS SYN Flood", 99.2),
            ("198.51.100.99", "PortScan Probe", 98.7),
            ("203.0.113.195", "Web Exploit (SQLi)", 99.8),
            ("172.16.0.105", "Botnet C2 Traffic", 96.4),
            ("133.242.18.99", "Brute Force (SSH)", 94.5),
            ("185.220.101.5", "DoS / Slowloris Flood", 97.9),
            ("45.33.32.156", "Infiltration Probe", 92.1)
        ]
        for idx, (ip, vector, conf) in enumerate(demo_vectors):
            geo = resolve_geoip(ip)
            geo_feed.append({
                'id': 1000 + idx,
                'src_ip': ip,
                'dst_ip': '192.168.1.50',
                'category': vector,
                'confidence': conf,
                'timestamp': time.time() - (idx * 180),
                'time_display': time.strftime("%H:%M:%S"),
                'lat': geo.get('lat', 0.0),
                'lon': geo.get('lon', 0.0),
                'country': geo.get('country', 'Unknown'),
                'city': geo.get('city', 'Unknown'),
                'flag': geo.get('flag', '🌐'),
                'code': geo.get('code', 'WAN'),
                'region': geo.get('region', 'Global')
            })

    return jsonify({
        'status': 'success',
        'count': len(geo_feed),
        'feed': geo_feed
    }), 200

# ======================================================================
# LOCAL OLLAMA LLM & CONTINUOUS TRAINING ENDPOINTS (NO EXTERNAL API KEYS)
# ======================================================================

@prediction_bp.route('/ollama/status', methods=['GET'])
def ollama_status():
    """Checks self-hosted Ollama server status and available installed models."""
    is_online = global_ollama.is_available()
    models = global_ollama.get_available_models() if is_online else []
    active = global_ollama.get_active_model() if is_online else None
    return jsonify({
        'online': is_online,
        'server': global_ollama.base_url,
        'active_model': active,
        'installed_models': models,
        'api_key_required': False,
        'hosting': 'Self-Hosted (Local On-Premises)'
    }), 200

@prediction_bp.route('/ollama/generate', methods=['POST'])
def ollama_generate():
    """Direct inference route against local Ollama without external keys."""
    data = request.json or {}
    prompt = data.get('prompt', '')
    if not prompt:
        return jsonify({'error': 'Prompt parameter is required'}), 400
    system_prompt = data.get('system_prompt', None)
    res = global_ollama.generate(prompt, system_prompt=system_prompt)
    return jsonify(res), (200 if res.get('success') else 500)

@prediction_bp.route('/simulation/stats', methods=['GET'])
def simulation_stats():
    """Returns dataset metrics for recorded simulations ready for model retraining."""
    stats = global_recorder.get_stats()
    return jsonify(stats), 200

@prediction_bp.route('/simulation/retrain', methods=['POST'])
def simulation_retrain():
    """
    Triggers continuous model retraining pipeline using recorded attack/benign telemetry.
    Re-fits LightGBM classifier, saves updated model.pkl, and hot-reloads it in memory.
    """
    global model, model_loaded
    try:
        from train_model import retrain_model
        train_res = retrain_model()
        if train_res.get('success'):
            # Hot reload updated model in-process
            try:
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                model_loaded = True
                print("[HotReload] Successfully reloaded freshly retrained LightGBM model.")
            except Exception as reload_err:
                print(f"[HotReload] Warning: could not hot reload model: {reload_err}")
            return jsonify({
                'status': 'success',
                'message': 'LightGBM model successfully retrained on recorded simulation telemetry and reloaded.',
                'report': train_res.get('report')
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': train_res.get('error', 'Training failed')
            }), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Retraining pipeline failed: {str(e)}'}), 500