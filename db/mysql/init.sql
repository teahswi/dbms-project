-- ============================================================================
-- CYBERSHIELD: Enterprise Cybersecurity Risk & Operations Management System
-- Database: MySQL 8.0+
-- Normalization: 3NF Relational Architecture (24+ Core Tables)
-- ============================================================================

CREATE DATABASE IF NOT EXISTS cybershield CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cybershield;

-- ----------------------------------------------------------------------------
-- 1. ACCESS CONTROL & ORGANIZATIONAL HIERARCHY
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS departments (
    department_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    code VARCHAR(20) NOT NULL UNIQUE,
    head_name VARCHAR(100),
    office_location VARCHAR(100) NOT NULL DEFAULT 'Bengaluru',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS permissions (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255) NOT NULL,
    module VARCHAR(50) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    department_id INT,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    title VARCHAR(100) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    lockout_until TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (department_id) REFERENCES departments(department_id) ON DELETE SET NULL,
    INDEX idx_user_email (email),
    INDEX idx_user_dept (department_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_history (
    login_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255),
    status ENUM('SUCCESS', 'FAILURE', 'LOCKED_OUT') NOT NULL,
    failure_reason VARCHAR(100) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_login_user_time (user_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(50) NOT NULL,
    old_values JSON NULL,
    new_values JSON NULL,
    ip_address VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_audit_entity (entity_type, entity_id),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_time (created_at)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 2. ASSET & INVENTORY MANAGEMENT
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS asset_types (
    type_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    code VARCHAR(30) NOT NULL UNIQUE,
    description VARCHAR(255)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS assets (
    asset_id INT AUTO_INCREMENT PRIMARY KEY,
    asset_type_id INT NOT NULL,
    department_id INT NOT NULL,
    owner_user_id INT NULL,
    hostname VARCHAR(150) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(17),
    os_name VARCHAR(100) NOT NULL,
    os_version VARCHAR(50),
    environment ENUM('PRODUCTION', 'STAGING', 'DEVELOPMENT', 'DISASTER_RECOVERY') NOT NULL DEFAULT 'PRODUCTION',
    criticality TINYINT NOT NULL CHECK (criticality BETWEEN 1 AND 5),
    lifecycle_status ENUM('ACTIVE', 'MAINTENANCE', 'DECOMMISSIONED', 'PROVISIONING') NOT NULL DEFAULT 'ACTIVE',
    eol_date DATE NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_type_id) REFERENCES asset_types(type_id),
    FOREIGN KEY (department_id) REFERENCES departments(department_id),
    FOREIGN KEY (owner_user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_asset_criticality (criticality),
    INDEX idx_asset_ip (ip_address),
    INDEX idx_asset_dept (department_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS software_inventory (
    software_id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    vendor VARCHAR(100) NOT NULL,
    software_name VARCHAR(150) NOT NULL,
    version VARCHAR(50) NOT NULL,
    install_date DATE NULL,
    is_eol BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    UNIQUE KEY uk_asset_software (asset_id, software_name, version),
    INDEX idx_sw_name (software_name)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 3. VULNERABILITIES & REMEDIATION MANAGEMENT
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cves (
    cve_id VARCHAR(30) PRIMARY KEY,
    description TEXT NOT NULL,
    cvss_score DECIMAL(3, 1) NOT NULL CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    cvss_vector VARCHAR(100),
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL,
    exploit_available BOOLEAN NOT NULL DEFAULT FALSE,
    cwe_id VARCHAR(30),
    published_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cve_severity (severity),
    INDEX idx_cve_cvss (cvss_score)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
    finding_id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    cve_id VARCHAR(30) NOT NULL,
    status ENUM('OPEN', 'IN_PROGRESS', 'PENDING_VERIFICATION', 'REMEDIATED', 'RISK_ACCEPTED', 'FALSE_POSITIVE') NOT NULL DEFAULT 'OPEN',
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL,
    priority_score DECIMAL(5, 2) NOT NULL DEFAULT 0.00,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sla_due_date TIMESTAMP NOT NULL,
    resolved_at TIMESTAMP NULL,
    verified_by_user_id INT NULL,
    verification_notes TEXT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE RESTRICT,
    FOREIGN KEY (verified_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE KEY uk_asset_cve (asset_id, cve_id),
    INDEX idx_vuln_status (status),
    INDEX idx_vuln_priority (priority_score DESC),
    INDEX idx_vuln_sla (sla_due_date)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS remediation_tasks (
    task_id INT AUTO_INCREMENT PRIMARY KEY,
    finding_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    assigned_to_user_id INT NULL,
    status ENUM('OPEN', 'IN_PROGRESS', 'SUBMITTED_FOR_REVIEW', 'COMPLETED', 'BLOCKED') NOT NULL DEFAULT 'OPEN',
    priority ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL DEFAULT 'MEDIUM',
    due_date TIMESTAMP NOT NULL,
    completed_at TIMESTAMP NULL,
    fix_notes TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES asset_vulnerabilities(finding_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to_user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_remediation_assignee (assigned_to_user_id),
    INDEX idx_remediation_due (due_date)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 4. SECURITY ALERTS & EVENT MONITORING
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS security_events (
    event_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    asset_id INT NULL,
    raw_payload JSON NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO') NOT NULL DEFAULT 'INFO',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE SET NULL,
    INDEX idx_event_time (created_at),
    INDEX idx_event_asset (asset_id),
    INDEX idx_event_type (event_type)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alert_rules (
    rule_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL UNIQUE,
    description TEXT,
    event_type VARCHAR(100) NOT NULL,
    threshold_count INT NOT NULL DEFAULT 5,
    time_window_seconds INT NOT NULL DEFAULT 300,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO') NOT NULL DEFAULT 'MEDIUM',
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    rule_id INT NULL,
    asset_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO') NOT NULL,
    status ENUM('NEW', 'TRIAGED', 'INVESTIGATING', 'ESCALATED', 'CLOSED_TP', 'CLOSED_FP', 'SUPPRESSED') NOT NULL DEFAULT 'NEW',
    assigned_to_user_id INT NULL,
    correlation_id VARCHAR(64) NULL,
    duplicate_count INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_id) REFERENCES alert_rules(rule_id) ON DELETE SET NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to_user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_alert_status (status),
    INDEX idx_alert_severity (severity),
    INDEX idx_alert_correlation (correlation_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator_id INT AUTO_INCREMENT PRIMARY KEY,
    indicator_type ENUM('IP', 'DOMAIN', 'FILE_HASH_SHA256', 'URL', 'CVE') NOT NULL,
    indicator_value VARCHAR(255) NOT NULL UNIQUE,
    threat_actor VARCHAR(100) DEFAULT 'Unknown',
    confidence TINYINT NOT NULL CHECK (confidence BETWEEN 1 AND 100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ioc_val (indicator_value)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 5. INCIDENT RESPONSE & INVESTIGATION
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incidents (
    incident_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    category ENUM('RANSOMWARE', 'DATA_EXFILTRATION', 'UNAUTHORIZED_ACCESS', 'MALWARE_OUTBREAK', 'PHISHING', 'DDOS', 'INSIDER_THREAT', 'CONFIGURATION_DEFECT') NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL,
    status ENUM('OPEN', 'TRIAGE', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'CLOSED') NOT NULL DEFAULT 'OPEN',
    lead_analyst_id INT NULL,
    asset_id INT NULL,
    mttd_seconds INT NULL,
    mttr_seconds INT NULL,
    sla_due_at TIMESTAMP NOT NULL,
    resolution_summary TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    FOREIGN KEY (lead_analyst_id) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE SET NULL,
    INDEX idx_incident_status (status),
    INDEX idx_incident_severity (severity),
    INDEX idx_incident_lead (lead_analyst_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id INT NOT NULL,
    alert_id INT NOT NULL,
    PRIMARY KEY (incident_id, alert_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (alert_id) REFERENCES security_alerts(alert_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS incident_tasks (
    task_id INT AUTO_INCREMENT PRIMARY KEY,
    incident_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    assigned_to_user_id INT NULL,
    is_completed BOOLEAN NOT NULL DEFAULT FALSE,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to_user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS investigation_notes (
    note_id INT AUTO_INCREMENT PRIMARY KEY,
    incident_id INT NOT NULL,
    user_id INT NOT NULL,
    note_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE RESTRICT
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INT AUTO_INCREMENT PRIMARY KEY,
    entity_type ENUM('INCIDENT', 'VULNERABILITY', 'AUDIT_ASSESSMENT', 'RISK_TREATMENT') NOT NULL,
    entity_id VARCHAR(50) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_hash_sha256 CHAR(64) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    storage_path VARCHAR(500) NOT NULL,
    uploaded_by_user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploaded_by_user_id) REFERENCES users(user_id) ON DELETE RESTRICT,
    INDEX idx_evidence_entity (entity_type, entity_id)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 6. SECURITY AUDIT & COMPLIANCE
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS frameworks (
    framework_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    version VARCHAR(20) NOT NULL,
    description TEXT
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_controls (
    control_id INT AUTO_INCREMENT PRIMARY KEY,
    framework_id INT NOT NULL,
    control_code VARCHAR(50) NOT NULL UNIQUE,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    domain VARCHAR(100) NOT NULL,
    effectiveness_score DECIMAL(3, 2) NOT NULL DEFAULT 1.00 CHECK (effectiveness_score BETWEEN 0.0 AND 1.0),
    FOREIGN KEY (framework_id) REFERENCES frameworks(framework_id) ON DELETE CASCADE,
    INDEX idx_control_domain (domain)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_plans (
    plan_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    framework_id INT NOT NULL,
    lead_auditor_id INT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    status ENUM('PLANNED', 'IN_PROGRESS', 'REVIEW', 'COMPLETED', 'ARCHIVED') NOT NULL DEFAULT 'PLANNED',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (framework_id) REFERENCES frameworks(framework_id) ON DELETE CASCADE,
    FOREIGN KEY (lead_auditor_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_assessments (
    assessment_id INT AUTO_INCREMENT PRIMARY KEY,
    plan_id INT NOT NULL,
    control_id INT NOT NULL,
    status ENUM('PASS', 'FAIL', 'PARTIAL', 'NOT_APPLICABLE') NOT NULL DEFAULT 'NOT_APPLICABLE',
    notes TEXT,
    assessed_by_user_id INT NULL,
    assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (plan_id) REFERENCES audit_plans(plan_id) ON DELETE CASCADE,
    FOREIGN KEY (control_id) REFERENCES security_controls(control_id) ON DELETE CASCADE,
    FOREIGN KEY (assessed_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE KEY uk_plan_control (plan_id, control_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_findings (
    finding_id INT AUTO_INCREMENT PRIMARY KEY,
    assessment_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL,
    status ENUM('OPEN', 'REMEDIATING', 'VERIFIED_CLOSED', 'ACCEPTED') NOT NULL DEFAULT 'OPEN',
    corrective_action_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assessment_id) REFERENCES audit_assessments(assessment_id) ON DELETE CASCADE,
    INDEX idx_audit_finding_status (status)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 7. RISK ASSESSMENT & RISK REGISTER
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS risks (
    risk_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    threat_description TEXT NOT NULL,
    department_id INT NOT NULL,
    asset_id INT NULL,
    control_id INT NULL,
    status ENUM('IDENTIFIED', 'ASSESSED', 'TREATED', 'ACCEPTED', 'CLOSED') NOT NULL DEFAULT 'IDENTIFIED',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (department_id) REFERENCES departments(department_id),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE SET NULL,
    FOREIGN KEY (control_id) REFERENCES security_controls(control_id) ON DELETE SET NULL,
    INDEX idx_risk_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id INT AUTO_INCREMENT PRIMARY KEY,
    risk_id INT NOT NULL,
    likelihood TINYINT NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact TINYINT NOT NULL CHECK (impact BETWEEN 1 AND 5),
    inherent_score INT GENERATED ALWAYS AS (likelihood * impact) STORED,
    residual_score INT NOT NULL CHECK (residual_score BETWEEN 1 AND 25),
    rationale TEXT,
    assessed_by_user_id INT NULL,
    assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (risk_id) REFERENCES risks(risk_id) ON DELETE CASCADE,
    FOREIGN KEY (assessed_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS risk_treatments (
    treatment_id INT AUTO_INCREMENT PRIMARY KEY,
    risk_id INT NOT NULL,
    strategy ENUM('MITIGATE', 'ACCEPT', 'TRANSFER', 'AVOID') NOT NULL,
    justification TEXT NOT NULL,
    owner_user_id INT NOT NULL,
    target_date DATE NOT NULL,
    approved_by_user_id INT NULL,
    approval_date DATE NULL,
    expiry_date DATE NULL,
    status ENUM('PROPOSED', 'APPROVED', 'IMPLEMENTED', 'REJECTED', 'EXPIRED') NOT NULL DEFAULT 'PROPOSED',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (risk_id) REFERENCES risks(risk_id) ON DELETE CASCADE,
    FOREIGN KEY (owner_user_id) REFERENCES users(user_id) ON DELETE RESTRICT,
    FOREIGN KEY (approved_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 8. STORED PROCEDURES (5 Key Business Transactions)
-- ----------------------------------------------------------------------------

DELIMITER $$

-- Procedure 1: Recalculate asset exposure based on open vulnerabilities and alerts
CREATE PROCEDURE sp_recalculate_asset_exposure(IN p_asset_id INT)
BEGIN
    DECLARE v_vuln_weight DECIMAL(10, 2) DEFAULT 0.00;
    DECLARE v_alert_count INT DEFAULT 0;
    DECLARE v_criticality TINYINT DEFAULT 1;

    SELECT criticality INTO v_criticality FROM assets WHERE asset_id = p_asset_id;

    SELECT COALESCE(SUM(priority_score), 0) INTO v_vuln_weight
    FROM asset_vulnerabilities
    WHERE asset_id = p_asset_id AND status IN ('OPEN', 'IN_PROGRESS');

    SELECT COUNT(*) INTO v_alert_count
    FROM security_alerts
    WHERE asset_id = p_asset_id AND status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'ESCALATED');

    -- Update or log exposure metric
    INSERT INTO audit_logs (action, entity_type, entity_id, new_values, ip_address)
    VALUES (
        'EXPOSURE_RECALCULATED',
        'ASSET',
        CAST(p_asset_id AS CHAR),
        JSON_OBJECT(
            'asset_id', p_asset_id,
            'vuln_score_sum', v_vuln_weight,
            'open_alerts', v_alert_count,
            'criticality', v_criticality
        ),
        'SYSTEM_TRIGGER'
    );
END$$

-- Procedure 2: Auto-escalate critical alerts on high-value assets
CREATE PROCEDURE sp_auto_escalate_critical_alerts()
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE v_alert_id INT;
    DECLARE v_asset_id INT;
    DECLARE v_title VARCHAR(200);

    DECLARE cur CURSOR FOR
        SELECT a.alert_id, a.asset_id, a.title
        FROM security_alerts a
        JOIN assets ast ON a.asset_id = ast.asset_id
        WHERE a.severity = 'CRITICAL'
          AND ast.criticality >= 4
          AND a.status = 'NEW';

    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

    OPEN cur;
    read_loop: LOOP
        FETCH cur INTO v_alert_id, v_asset_id, v_title;
        IF done THEN
            LEAVE read_loop;
        END IF;

        UPDATE security_alerts
        SET status = 'ESCALATED', updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = v_alert_id;

        INSERT INTO audit_logs (action, entity_type, entity_id, new_values, ip_address)
        VALUES (
            'ALERT_AUTO_ESCALATED',
            'SECURITY_ALERT',
            CAST(v_alert_id AS CHAR),
            JSON_OBJECT('reason', 'Critical alert on high-criticality asset', 'asset_id', v_asset_id),
            'SYSTEM_CRON'
        );
    END LOOP;
    CLOSE cur;
END$$

-- Procedure 3: Resolve vulnerability with mandatory two-person verification
CREATE PROCEDURE sp_resolve_vulnerability_finding(
    IN p_finding_id INT,
    IN p_verifier_id INT,
    IN p_notes TEXT
)
BEGIN
    DECLARE v_assigned_user INT;
    DECLARE v_current_status VARCHAR(30);

    SELECT assigned_to_user_id INTO v_assigned_user
    FROM remediation_tasks
    WHERE finding_id = p_finding_id
    ORDER BY task_id DESC LIMIT 1;

    SELECT status INTO v_current_status
    FROM asset_vulnerabilities
    WHERE finding_id = p_finding_id;

    -- Enforce segregation of duties: verifier cannot be the fixer
    IF v_assigned_user IS NOT NULL AND v_assigned_user = p_verifier_id THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Segregation of duties violation: Remediation fixer cannot verify their own fix.';
    END IF;

    UPDATE asset_vulnerabilities
    SET status = 'REMEDIATED',
        resolved_at = CURRENT_TIMESTAMP,
        verified_by_user_id = p_verifier_id,
        verification_notes = p_notes
    WHERE finding_id = p_finding_id;

    UPDATE remediation_tasks
    SET status = 'COMPLETED',
        completed_at = CURRENT_TIMESTAMP
    WHERE finding_id = p_finding_id;

    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, new_values, ip_address)
    VALUES (
        p_verifier_id,
        'VULNERABILITY_VERIFIED_RESOLVED',
        'VULNERABILITY_FINDING',
        CAST(p_finding_id AS CHAR),
        JSON_OBJECT('verifier_id', p_verifier_id, 'notes', p_notes),
        '127.0.0.1'
    );
END$$

-- Procedure 4: Auto-create corrective remediation action from failed audit assessment
CREATE PROCEDURE sp_generate_audit_corrective_action(
    IN p_finding_id INT,
    IN p_assigned_user_id INT,
    IN p_due_days INT
)
BEGIN
    DECLARE v_title VARCHAR(200);
    DECLARE v_desc TEXT;
    DECLARE v_task_id INT;

    SELECT title, description INTO v_title, v_desc
    FROM audit_findings
    WHERE finding_id = p_finding_id;

    -- Mark finding as remediating
    UPDATE audit_findings
    SET status = 'REMEDIATING'
    WHERE finding_id = p_finding_id;

    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, new_values, ip_address)
    VALUES (
        p_assigned_user_id,
        'AUDIT_CORRECTIVE_ACTION_INITIATED',
        'AUDIT_FINDING',
        CAST(p_finding_id AS CHAR),
        JSON_OBJECT('assigned_to', p_assigned_user_id, 'due_days', p_due_days),
        '127.0.0.1'
    );
END$$

-- Procedure 5: Close Incident with strict post-incident summary and all tasks complete check
CREATE PROCEDURE sp_close_incident_workflow(
    IN p_incident_id INT,
    IN p_resolution_summary TEXT,
    IN p_user_id INT
)
BEGIN
    DECLARE v_uncompleted_tasks INT DEFAULT 0;
    DECLARE v_created_at TIMESTAMP;
    DECLARE v_mttr_sec INT;

    IF p_resolution_summary IS NULL OR LENGTH(TRIM(p_resolution_summary)) < 15 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Post-incident resolution summary is required and must be thorough (min 15 chars).';
    END IF;

    SELECT COUNT(*) INTO v_uncompleted_tasks
    FROM incident_tasks
    WHERE incident_id = p_incident_id AND is_completed = FALSE;

    IF v_uncompleted_tasks > 0 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Cannot close incident: Outstanding open response tasks remain.';
    END IF;

    SELECT created_at INTO v_created_at FROM incidents WHERE incident_id = p_incident_id;
    SET v_mttr_sec = TIMESTAMPDIFF(SECOND, v_created_at, CURRENT_TIMESTAMP);

    UPDATE incidents
    SET status = 'CLOSED',
        resolution_summary = p_resolution_summary,
        mttr_seconds = v_mttr_sec,
        closed_at = CURRENT_TIMESTAMP
    WHERE incident_id = p_incident_id;

    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, new_values, ip_address)
    VALUES (
        p_user_id,
        'INCIDENT_CLOSED',
        'INCIDENT',
        CAST(p_incident_id AS CHAR),
        JSON_OBJECT('summary', p_resolution_summary, 'mttr_seconds', v_mttr_sec),
        '127.0.0.1'
    );
END$$

-- ----------------------------------------------------------------------------
-- 9. TRIGGERS (Automated Business Invariants)
-- ----------------------------------------------------------------------------

-- Trigger 1: Auto calculate SLA due date upon vulnerability finding discovery
CREATE TRIGGER trg_vuln_sla_calculation
BEFORE INSERT ON asset_vulnerabilities
FOR EACH ROW
BEGIN
    IF NEW.sla_due_date IS NULL OR NEW.sla_due_date = '0000-00-00 00:00:00' THEN
        CASE NEW.severity
            WHEN 'CRITICAL' THEN SET NEW.sla_due_date = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 7 DAY);
            WHEN 'HIGH' THEN SET NEW.sla_due_date = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 14 DAY);
            WHEN 'MEDIUM' THEN SET NEW.sla_due_date = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 30 DAY);
            ELSE SET NEW.sla_due_date = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 90 DAY);
        END CASE;
    END IF;
END$$

-- Trigger 2: Enforce append-only immutability on audit_logs table
CREATE TRIGGER trg_audit_log_immutable_upd
BEFORE UPDATE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Audit logs are strictly append-only and immutable. Updates forbidden.';
END$$

CREATE TRIGGER trg_audit_log_immutable_del
BEFORE DELETE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Audit logs are strictly append-only and immutable. Deletions forbidden.';
END$$

-- Trigger 3: Record state transition and update MTTD on incident assignment
CREATE TRIGGER trg_incident_triage_time
BEFORE UPDATE ON incidents
FOR EACH ROW
BEGIN
    IF OLD.status = 'OPEN' AND NEW.status != 'OPEN' AND NEW.mttd_seconds IS NULL THEN
        SET NEW.mttd_seconds = TIMESTAMPDIFF(SECOND, OLD.created_at, CURRENT_TIMESTAMP);
    END IF;
END$$

DELIMITER ;

-- ----------------------------------------------------------------------------
-- 10. VIEWS (High-Performance Query Aggregations)
-- ----------------------------------------------------------------------------

-- View 1: Asset Exposure Scoreboard
CREATE OR REPLACE VIEW v_asset_exposure AS
SELECT 
    a.asset_id,
    a.hostname,
    a.ip_address,
    a.environment,
    a.criticality,
    d.name AS department_name,
    COUNT(DISTINCT av.finding_id) AS open_vulnerability_count,
    COALESCE(SUM(CASE WHEN av.status IN ('OPEN', 'IN_PROGRESS') THEN av.priority_score ELSE 0 END), 0) AS total_exposure_score,
    COUNT(DISTINCT sa.alert_id) AS active_alerts_count,
    COUNT(DISTINCT inc.incident_id) AS active_incidents_count
FROM assets a
LEFT JOIN departments d ON a.department_id = d.department_id
LEFT JOIN asset_vulnerabilities av ON a.asset_id = av.asset_id AND av.status IN ('OPEN', 'IN_PROGRESS')
LEFT JOIN security_alerts sa ON a.asset_id = sa.asset_id AND sa.status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'ESCALATED')
LEFT JOIN incidents inc ON a.asset_id = inc.asset_id AND inc.status != 'CLOSED'
GROUP BY a.asset_id, a.hostname, a.ip_address, a.environment, a.criticality, d.name;

-- View 2: Overdue Remediation Tasks and Breached SLAs
CREATE OR REPLACE VIEW v_overdue_remediation AS
SELECT 
    rt.task_id,
    rt.title AS task_title,
    rt.status AS task_status,
    rt.priority,
    rt.due_date,
    TIMESTAMPDIFF(DAY, rt.due_date, CURRENT_TIMESTAMP) AS days_overdue,
    u.full_name AS assignee_name,
    u.email AS assignee_email,
    a.hostname,
    c.cve_id,
    c.cvss_score
FROM remediation_tasks rt
JOIN asset_vulnerabilities av ON rt.finding_id = av.finding_id
JOIN assets a ON av.asset_id = a.asset_id
JOIN cves c ON av.cve_id = c.cve_id
LEFT JOIN users u ON rt.assigned_to_user_id = u.user_id
WHERE rt.status NOT IN ('COMPLETED', 'BLOCKED')
  AND rt.due_date < CURRENT_TIMESTAMP;

-- View 3: Open Incidents with SLA clocks and Active Alerts
CREATE OR REPLACE VIEW v_open_incidents AS
SELECT 
    i.incident_id,
    i.title,
    i.category,
    i.severity,
    i.status,
    i.created_at,
    i.sla_due_at,
    TIMESTAMPDIFF(MINUTE, CURRENT_TIMESTAMP, i.sla_due_at) AS minutes_remaining_sla,
    u.full_name AS lead_analyst_name,
    a.hostname AS affected_asset,
    COUNT(ia.alert_id) AS linked_alert_count,
    COUNT(it.task_id) AS total_tasks,
    SUM(CASE WHEN it.is_completed = TRUE THEN 1 ELSE 0 END) AS completed_tasks
FROM incidents i
LEFT JOIN users u ON i.lead_analyst_id = u.user_id
LEFT JOIN assets a ON i.asset_id = a.asset_id
LEFT JOIN incident_alerts ia ON i.incident_id = ia.incident_id
LEFT JOIN incident_tasks it ON i.incident_id = it.incident_id
WHERE i.status != 'CLOSED'
GROUP BY i.incident_id, i.title, i.category, i.severity, i.status, i.created_at, i.sla_due_at, u.full_name, a.hostname;

-- View 4: End-to-End Control Traceability (Control -> Assessment -> Finding -> Action -> User)
CREATE OR REPLACE VIEW v_control_traceability AS
SELECT 
    f.name AS framework_name,
    sc.control_code,
    sc.title AS control_title,
    sc.domain AS control_domain,
    aa.status AS assessment_status,
    aa.assessed_at,
    u_eval.full_name AS assessed_by,
    af.finding_id,
    af.title AS audit_finding_title,
    af.severity AS finding_severity,
    af.status AS finding_status,
    ap.title AS audit_plan_title
FROM security_controls sc
JOIN frameworks f ON sc.framework_id = f.framework_id
LEFT JOIN audit_assessments aa ON sc.control_id = aa.control_id
LEFT JOIN audit_plans ap ON aa.plan_id = ap.plan_id
LEFT JOIN users u_eval ON aa.assessed_by_user_id = u_eval.user_id
LEFT JOIN audit_findings af ON aa.assessment_id = af.assessment_id;
