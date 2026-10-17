"""
CyberShield Constants & Enumerations
"""

class Roles:
    SECURITY_ANALYST = "Security Analyst"
    IT_INFRA_ENGINEER = "IT Infrastructure Engineer"
    COMPLIANCE_AUDITOR = "Compliance Auditor"
    SECURITY_MANAGER = "Security Manager"
    ADMIN = "Admin"

    ALL_ROLES = [
        SECURITY_ANALYST,
        IT_INFRA_ENGINEER,
        COMPLIANCE_AUDITOR,
        SECURITY_MANAGER,
        ADMIN
    ]

class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}

class AssetEnvironment:
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    DISASTER_RECOVERY = "DISASTER_RECOVERY"

class AssetCriticality:
    TIER_1 = 5  # Mission Critical / Core Production
    TIER_2 = 4  # High / Client-Facing
    TIER_3 = 3  # Medium / Internal Operations
    TIER_4 = 2  # Low / Dev & Test
    TIER_5 = 1  # Informational / Sandbox

class IncidentStatus:
    OPEN = "OPEN"
    TRIAGE = "TRIAGE"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    CLOSED = "CLOSED"

    # State Machine: allowed transitions
    VALID_TRANSITIONS = {
        OPEN: [TRIAGE, CLOSED],
        TRIAGE: [CONTAINMENT, CLOSED],
        CONTAINMENT: [ERADICATION, CLOSED],
        ERADICATION: [RECOVERY, CLOSED],
        RECOVERY: [CLOSED],
        CLOSED: [] # Terminal
    }

class VulnerabilityStatus:
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    REMEDIATED = "REMEDIATED"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

    VALID_TRANSITIONS = {
        OPEN: [IN_PROGRESS, RISK_ACCEPTED, FALSE_POSITIVE],
        IN_PROGRESS: [PENDING_VERIFICATION, RISK_ACCEPTED, OPEN],
        PENDING_VERIFICATION: [REMEDIATED, IN_PROGRESS], # Must be verified by separate persona
        REMEDIATED: [],
        RISK_ACCEPTED: [OPEN],
        FALSE_POSITIVE: [OPEN]
    }

class AlertStatus:
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    CLOSED_TP = "CLOSED_TP"
    CLOSED_FP = "CLOSED_FP"
    SUPPRESSED = "SUPPRESSED"

class RiskTreatmentStrategy:
    MITIGATE = "MITIGATE"
    ACCEPT = "ACCEPT"
    TRANSFER = "TRANSFER"
    AVOID = "AVOID"
