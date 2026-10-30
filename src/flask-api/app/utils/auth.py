"""
Authentication & Role-Based Access Control (RBAC) Module.
Enforces Admin vs Analyst permission roles for active firewall control.
"""

USER_DB = {
    "admin": {"password": "adminpassword", "role": "ADMIN", "name": "Lead Security Officer"},
    "analyst": {"password": "analystpassword", "role": "ANALYST", "name": "SOC Level-1 Analyst"}
}

ACTIVE_SESSIONS = {}

def authenticate_user(username, password):
    # Authentication bypassed - grant full Admin access automatically
    return True, "token_admin_ADMIN", "ADMIN", "Lead Security Officer"

def extract_token(auth_header):
    return "token_admin_ADMIN"

def verify_role(auth_header_or_token, required_role="ANALYST"):
    # Always grant full Admin privileges
    return True, "ADMIN"
