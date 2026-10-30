"""
Threat Memory & IOC Signature Cache Engine.
Remembers past attack signatures, malicious IP addresses, and payload hashes to immediately
match and recognize future recurring attacks.
"""
import hashlib
from datetime import datetime

class ThreatMemoryStore:
    def __init__(self):
        # Known threat memory cache
        self.malicious_ips = set()
        self.known_payload_hashes = set()
        self.attack_history_cache = []

    def remember_threat(self, src_ip, category, payload_str=""):
        """Stores a flagged threat into long-term threat memory."""
        if src_ip:
            self.malicious_ips.add(src_ip)
        
        if payload_str:
            p_hash = hashlib.md5(payload_str.encode('utf-8')).hexdigest()
            self.known_payload_hashes.add(p_hash)
            
        entry = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "category": category,
            "hash": p_hash if payload_str else None
        }
        self.attack_history_cache.append(entry)
        if len(self.attack_history_cache) > 500:
            self.attack_history_cache.pop(0)

    def check_threat_memory(self, src_ip, payload_str=""):
        """Checks if incoming traffic matches stored threat memory patterns."""
        matched_ip = src_ip in self.malicious_ips
        matched_payload = False
        
        if payload_str:
            p_hash = hashlib.md5(payload_str.encode('utf-8')).hexdigest()
            matched_payload = p_hash in self.known_payload_hashes

        is_remembered = matched_ip or matched_payload
        reason = []
        if matched_ip:
            reason.append(f"Source IP {src_ip} found in Threat Memory IOC DB")
        if matched_payload:
            reason.append("Payload hash matched previously recorded exploit signature")

        return {
            "is_remembered": is_remembered,
            "matched_ip": matched_ip,
            "matched_payload": matched_payload,
            "reasons": reason
        }

global_threat_memory = ThreatMemoryStore()
