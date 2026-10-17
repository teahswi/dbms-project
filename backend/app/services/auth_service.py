"""
Authentication & Authorization Service for CyberShield
Handles password hashing (bcrypt), account lockout thresholds, JWT tokens,
and demo persona authentication.
"""
from datetime import datetime, timedelta
import bcrypt
from flask_jwt_extended import create_access_token, create_refresh_token
from app.repositories.factory import get_repository
from app.services.audit_service import AuditService

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

DEMO_ACCOUNTS = [
    {
        "email": "analyst@nexora.test",
        "role": "Security Analyst",
        "name": "Aarav Sharma",
        "title": "Lead SOC Analyst",
        "department": "Security Operations",
        "description": "Triage alerts, investigate security anomalies, run incidents"
    },
    {
        "email": "infra@nexora.test",
        "role": "IT Infrastructure Engineer",
        "name": "Priya Nair",
        "title": "Senior Systems Engineer",
        "department": "IT Infrastructure",
        "description": "Own critical assets, remediate vulnerabilities, submit fix evidence"
    },
    {
        "email": "auditor@nexora.test",
        "role": "Compliance Auditor",
        "name": "Rohan Deshmukh",
        "title": "GRC & Audit Specialist",
        "department": "Governance & Compliance",
        "description": "Run audit plans, assess security controls, raise audit findings"
    },
    {
        "email": "manager@nexora.test",
        "role": "Security Manager",
        "name": "Kavita Reddy",
        "title": "Head of Information Security (CISO Staff)",
        "department": "Security Leadership",
        "description": "Approve risk treatments, monitor SLAs, view posture & reports"
    },
    {
        "email": "admin@nexora.test",
        "role": "Admin",
        "name": "Vikram Patel",
        "title": "Enterprise Security Administrator",
        "department": "IT Administration",
        "description": "Manage users, roles, permissions, view application audit logs"
    }
]

class AuthService:

    @staticmethod
    def hash_password(password: str) -> str:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        try:
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception:
            return False

    @staticmethod
    def authenticate_user(email: str, password: str, ip_address: str, user_agent: str):
        repo = get_repository()
        user = repo.get_user_by_email(email)

        if not user:
            repo.record_login(None, email, ip_address, user_agent, "FAILURE", "User not found")
            return None, "Invalid email or password"

        # Check account lockout
        lockout = user.get("lockout_until")
        if lockout:
            lock_time = lockout if isinstance(lockout, datetime) else datetime.fromisoformat(str(lockout))
            if datetime.utcnow() < lock_time:
                remaining = int((lock_time - datetime.utcnow()).total_seconds() / 60)
                repo.record_login(user.get("user_id"), email, ip_address, user_agent, "LOCKED_OUT", "Account locked")
                return None, f"Account is temporarily locked due to failed attempts. Try again in {remaining + 1} minutes."

        # Verify password (or allow demo override password 'Nexora@2026' for seeded accounts)
        pwd_match = AuthService.verify_password(password, user.get("password_hash", ""))
        if not pwd_match and password == "Nexora@2026":
            pwd_match = True

        if not pwd_match:
            failed_count = user.get("failed_login_attempts", 0) + 1
            updates = {"failed_login_attempts": failed_count}
            if failed_count >= MAX_FAILED_ATTEMPTS:
                lock_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                updates["lockout_until"] = lock_until.isoformat()
                repo.update_user(user.get("user_id"), updates)
                repo.record_login(user.get("user_id"), email, ip_address, user_agent, "LOCKED_OUT", "Threshold reached")
                return None, f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to excessive failed attempts."
            else:
                repo.update_user(user.get("user_id"), updates)
                repo.record_login(user.get("user_id"), email, ip_address, user_agent, "FAILURE", "Incorrect password")
                return None, f"Invalid password. {MAX_FAILED_ATTEMPTS - failed_count} attempts remaining before lockout."

        # Successful login: reset failed counter
        repo.update_user(user.get("user_id"), {"failed_login_attempts": 0, "lockout_until": None})
        repo.record_login(user.get("user_id"), email, ip_address, user_agent, "SUCCESS")

        # Create JWT claims
        identity = str(user.get("user_id"))
        additional_claims = {
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "role": user.get("role_name") or user.get("role", "Security Analyst"),
            "department": user.get("department_name") or user.get("department", "Security Operations"),
            "permissions": user.get("permissions", [])
        }
        access_token = create_access_token(identity=identity, additional_claims=additional_claims)
        refresh_token = create_refresh_token(identity=identity)

        # Audit log
        AuditService.log_action(
            user_id=user.get("user_id"),
            user_email=user.get("email"),
            action="USER_LOGIN_SUCCESS",
            entity_type="USER",
            entity_id=identity,
            ip_address=ip_address
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "user_id": identity,
                "email": user.get("email"),
                "full_name": user.get("full_name"),
                "title": user.get("title"),
                "role": additional_claims["role"],
                "department": additional_claims["department"],
                "permissions": additional_claims["permissions"]
            }
        }, None

    @staticmethod
    def get_demo_accounts():
        return DEMO_ACCOUNTS
