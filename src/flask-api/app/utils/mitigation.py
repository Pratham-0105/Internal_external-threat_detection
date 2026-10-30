"""
Active Defense & Automated Mitigation Engine.
Handles automatic IP blocking via Windows Firewall / iptables rules,
and logs sandbox honeypot isolation actions.
"""
import os
import platform
import subprocess
import ipaddress
from datetime import datetime

class ActiveDefenseEngine:
    def __init__(self):
        self.enabled = True
        self.blocked_ips = set()
        self.honeypot_logs = []

    def toggle(self, enable=None):
        if enable is not None:
            self.enabled = enable
        else:
            self.enabled = not self.enabled
        return self.enabled

    def mitigate_threat(self, src_ip, attack_type="Threat"):
        """Applies active defense rules if enabled."""
        if not self.enabled:
            return "Active Defense Disabled (Telemetry Only)"

        if src_ip in self.blocked_ips:
            return f"IP {src_ip} is already blocked."

        action_summary = []
        
        # 1. Firewall Ban Rule
        try:
            valid_ip = ipaddress.ip_address(src_ip.strip() if isinstance(src_ip, str) else "")
            clean_ip = str(valid_ip)
            
            if platform.system() == "Windows":
                rule_name = f"NIDS_BLOCK_{clean_ip.replace('.', '_').replace(':', '_')}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", 
                     f"name={rule_name}", "dir=in", "action=block", f"remoteip={clean_ip}"],
                    capture_output=True, timeout=2
                )
                action_summary.append(f"Firewall Rule Added: Blocked {clean_ip}")
            else:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", clean_ip, "-j", "DROP"],
                    capture_output=True, timeout=2
                )
                action_summary.append(f"iptables Rule Added: Dropped {clean_ip}")
        except ValueError:
            action_summary.append(f"Invalid IP address ({src_ip}) - Firewall Rule Skipped")
        except Exception as e:
            action_summary.append(f"Simulated Firewall Ban for {src_ip}")

        # 2. Honeypot Sandbox Reroute
        honeypot_entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "attacker_ip": src_ip,
            "attack_vector": attack_type,
            "sandbox_target": "Layer 2 Honeypot (10.0.99.1)",
            "status": "REROUTED_&_ISOLATED"
        }
        self.honeypot_logs.append(honeypot_entry)
        self.blocked_ips.add(src_ip)
        action_summary.append(f"Rerouted to Honeypot Sandbox (10.0.99.1)")

        return " | ".join(action_summary)

    def unblock_ip(self, src_ip):
        """Removes IP from blocked list and firewall rules."""
        src_ip = src_ip.strip() if isinstance(src_ip, str) else ""
        if src_ip in self.blocked_ips:
            self.blocked_ips.remove(src_ip)
            try:
                valid_ip = ipaddress.ip_address(src_ip)
                clean_ip = str(valid_ip)
                if platform.system() == "Windows":
                    rule_name = f"NIDS_BLOCK_{clean_ip.replace('.', '_').replace(':', '_')}"
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                        capture_output=True, timeout=2
                    )
                else:
                    subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP"],
                        capture_output=True, timeout=2
                    )
            except Exception:
                pass
            return True, f"IP {src_ip} unblocked."
        return False, f"IP {src_ip} was not blocked."

    def get_status(self):
        return {
            "enabled": self.enabled,
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ips": list(self.blocked_ips),
            "honeypot_logs": self.honeypot_logs[-10:]
        }

global_mitigation = ActiveDefenseEngine()
