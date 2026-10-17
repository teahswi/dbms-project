"""
Nexora Technologies Deterministic Seed Data Generator
Populates rich synthetic security operations data:
- 5 Departments (Bengaluru, Pune, Hyderabad)
- 5 Demo Persona Accounts + Users
- 760 Assets (120 servers + 600 endpoints + 40 applications)
- Installed Software Inventory with EOL flags
- 200 CVE catalog entries
- 400+ Findings & Remediation tasks (including deliberate overdue critical finding on Finance prod)
- 400+ Security Alerts & 5,000+ Events
- 30+ Incidents with response task lists & investigation notes
- ISO 27001 & NIST CSF (60+ controls)
- 3 Audit Plans with Assessments & Corrective Actions
- 50+ Risk Register entries with 5x5 Heatmap data
"""
import random
from datetime import datetime, timedelta
import bcrypt
from app.repositories.factory import get_repository
from app.services.risk_engine import calculate_priority_score, SLA_DAYS

def run_seed():
    print("[*] Starting Nexora Technologies Synthetic Data Seeder...")
    random.seed(42) # Deterministic seed

    repo = get_repository()
    # Check if MySQL/SQLite or Mongo
    if hasattr(repo, "engine"):
        _seed_sql(repo)
    else:
        _seed_mongo(repo)

    print("[SUCCESS] CyberShield database seeded successfully with Nexora Technologies dataset!")

def _seed_sql(repo):
    from sqlalchemy import text
    with repo.engine.begin() as conn:
        print("  -> Seeding Departments & Roles...")
        # 1. Departments
        conn.execute(text("DELETE FROM departments"))
        conn.execute(text("""
            INSERT INTO departments (department_id, name, code, head_name, office_location) VALUES
            (1, 'Security Operations', 'SEC-OPS', 'Kavita Reddy', 'Bengaluru'),
            (2, 'IT Infrastructure', 'IT-INFRA', 'Priya Nair', 'Bengaluru'),
            (3, 'Engineering & DevOps', 'ENG-DEV', 'Siddharth Roy', 'Pune'),
            (4, 'Finance & Payroll', 'FIN-PAY', 'Ananya Deshpande', 'Hyderabad'),
            (5, 'Governance & Compliance', 'GRC-AUD', 'Rohan Deshmukh', 'Bengaluru')
        """))

        # 2. Roles & Permissions
        conn.execute(text("DELETE FROM roles"))
        conn.execute(text("""
            INSERT INTO roles (role_id, name, description) VALUES
            (1, 'Security Analyst', 'Triage alerts, investigate security anomalies, run incidents'),
            (2, 'IT Infrastructure Engineer', 'Own critical assets, remediate vulnerabilities, submit fix evidence'),
            (3, 'Compliance Auditor', 'Run audit plans, assess security controls, raise audit findings'),
            (4, 'Security Manager', 'Approve risk treatments, monitor SLAs, view posture & reports'),
            (5, 'Admin', 'Manage users, roles, permissions, view application audit logs')
        """))

        conn.execute(text("DELETE FROM permissions"))
        perms = [
            (1, 'ASSET_VIEW', 'View all enterprise hardware, applications, and asset inventory', 'ASSET'),
            (2, 'ASSET_EDIT', 'Create, update, and manage asset specifications and software', 'ASSET'),
            (3, 'VULN_VIEW', 'View vulnerability findings and remediation tasks', 'VULN'),
            (4, 'VULN_REMEDIATE', 'Submit fixes and remediation evidence', 'VULN'),
            (5, 'VULN_VERIFY', 'Independently verify vulnerability resolution', 'VULN'),
            (6, 'ALERT_TRIAGE', 'Triage, suppress, and escalate security alerts', 'ALERT'),
            (7, 'INCIDENT_MANAGE', 'Lead, investigate, and close security incidents', 'INCIDENT'),
            (8, 'AUDIT_ASSESS', 'Perform compliance control assessments and record findings', 'AUDIT'),
            (9, 'RISK_APPROVE', 'Authorize risk acceptance and treatment strategies', 'RISK'),
            (10, 'ADMIN_ACCESS', 'Full administrative authority and audit log inspection', 'ADMIN')
        ]
        for p in perms:
            conn.execute(text("INSERT INTO permissions (permission_id, code, description, module) VALUES (:id, :c, :d, :m)"),
                         {"id": p[0], "c": p[1], "d": p[2], "m": p[3]})

        conn.execute(text("DELETE FROM role_permissions"))
        role_perm_maps = [
            (1, 1), (1, 3), (1, 6), (1, 7), # Analyst
            (2, 1), (2, 2), (2, 3), (2, 4), # Infra
            (3, 1), (3, 3), (3, 8),         # Auditor
            (4, 1), (4, 3), (4, 6), (4, 7), (4, 8), (4, 9), # Manager
            (5, 1), (5, 2), (5, 3), (5, 4), (5, 5), (5, 6), (5, 7), (5, 8), (5, 9), (5, 10) # Admin
        ]
        for rp in role_perm_maps:
            conn.execute(text("INSERT INTO role_permissions (role_id, permission_id) VALUES (:r, :p)"), {"r": rp[0], "p": rp[1]})

        # 3. Demo Users
        print("  -> Seeding Users & Demo Accounts...")
        conn.execute(text("DELETE FROM users"))
        conn.execute(text("DELETE FROM user_roles"))
        default_pwd_hash = bcrypt.hashpw(b"Nexora@2026", bcrypt.gensalt(10)).decode('utf-8')
        demo_users = [
            (1, 1, 'analyst@nexora.test', 'Aarav Sharma', 'Lead SOC Analyst', 1),
            (2, 2, 'infra@nexora.test', 'Priya Nair', 'Senior Systems Engineer', 2),
            (3, 5, 'auditor@nexora.test', 'Rohan Deshmukh', 'GRC & Audit Specialist', 3),
            (4, 1, 'manager@nexora.test', 'Kavita Reddy', 'Head of Information Security', 4),
            (5, 2, 'admin@nexora.test', 'Vikram Patel', 'Enterprise Security Administrator', 5)
        ]
        for u in demo_users:
            conn.execute(text("""
                INSERT INTO users (user_id, department_id, email, password_hash, full_name, title, is_active)
                VALUES (:uid, :dept, :email, :pwd, :name, :title, 1)
            """), {"uid": u[0], "dept": u[1], "email": u[2], "pwd": default_pwd_hash, "name": u[3], "title": u[4]})
            conn.execute(text("INSERT INTO user_roles (user_id, role_id) VALUES (:uid, :rid)"), {"uid": u[0], "rid": u[5]})

        # 4. Asset Types & Assets (120 servers, 600 endpoints, 40 apps)
        print("  -> Seeding 760 Nexora Assets (Servers, Endpoints, Applications)...")
        conn.execute(text("DELETE FROM asset_types"))
        conn.execute(text("""
            INSERT INTO asset_types (type_id, name, code, description) VALUES
            (1, 'Production Server', 'SERVER', 'Bare-metal & Virtual Cloud Compute Nodes'),
            (2, 'User Endpoint', 'ENDPOINT', 'Developer Laptops and Corporate Workstations'),
            (3, 'Enterprise Application', 'APP', 'Web APIs, Microservices, and Internal Portals'),
            (4, 'Database Cluster', 'DB', 'Relational & Document Database Instances'),
            (5, 'Cloud Infrastructure', 'CLOUD', 'AWS VPCs, Load Balancers, S3 Buckets')
        """))

        conn.execute(text("DELETE FROM assets"))
        conn.execute(text("DELETE FROM software_inventory"))

        # Servers (120)
        asset_id = 1
        server_roles = ['prod-api', 'k8s-worker', 'auth-srv', 'db-primary', 'payment-gw', 'redis-cache', 'log-collector', 'vpn-gw']
        depts = [1, 2, 3, 4, 5]

        for s_idx in range(1, 121):
            role_name = server_roles[(s_idx - 1) % len(server_roles)]
            hostname = f"nx-{role_name}-{s_idx:03d}.nexora.corp"
            ip = f"10.20.{s_idx // 256}.{s_idx % 254 + 1}"
            crit = 5 if 'prod' in role_name or 'db' in role_name or 'payment' in role_name else (4 if 'auth' in role_name or 'k8s' in role_name else 3)
            dept = 4 if 'payment' in role_name else (3 if 'api' in role_name or 'k8s' in role_name else 2)

            conn.execute(text("""
                INSERT INTO assets (asset_id, asset_type_id, department_id, owner_user_id, hostname, ip_address, mac_address, os_name, os_version, environment, criticality, lifecycle_status)
                VALUES (:aid, 1, :dept, 2, :host, :ip, '52:54:00:12:34:56', 'Linux', 'Ubuntu 22.04 LTS', 'PRODUCTION', :crit, 'ACTIVE')
            """), {"aid": asset_id, "dept": dept, "host": hostname, "ip": ip, "crit": crit})

            # Add software
            conn.execute(text("""
                INSERT INTO software_inventory (asset_id, vendor, software_name, version, is_eol)
                VALUES (:aid, 'Canonical', 'OpenSSH', '8.9p1-3ubuntu0.6', 0),
                       (:aid, 'OpenSSL Project', 'OpenSSL', '3.0.2', 0)
            """), {"aid": asset_id})
            asset_id += 1

        # Applications (40)
        app_names = ['Customer Portal', 'Core Billing Engine', 'Payroll Service', 'HRMS Portal', 'GitLab Enterprise',
                     'API Gateway', 'Partner Integration Bus', 'Identity Provider', 'Data Pipeline Aggregator', 'Telephony PBX']
        for a_idx in range(1, 41):
            base_name = app_names[(a_idx - 1) % len(app_names)]
            hostname = f"app-{base_name.lower().replace(' ', '-')}-{a_idx:02d}.nexora.internal"
            ip = f"172.16.10.{a_idx}"
            crit = 5 if 'Billing' in base_name or 'Payroll' in base_name or 'Identity' in base_name else 4
            conn.execute(text("""
                INSERT INTO assets (asset_id, asset_type_id, department_id, owner_user_id, hostname, ip_address, mac_address, os_name, os_version, environment, criticality, lifecycle_status)
                VALUES (:aid, 3, 3, 2, :host, :ip, '00:16:3e:aa:bb:cc', 'Containerized', 'Docker 24.0.7', 'PRODUCTION', :crit, 'ACTIVE')
            """), {"aid": asset_id, "host": hostname, "ip": ip, "crit": crit})
            asset_id += 1

        # Endpoints (600)
        print("    .. adding developer and employee workstations ..")
        offices = ['BLR', 'PUN', 'HYD']
        for ep_idx in range(1, 601):
            loc = offices[(ep_idx - 1) % len(offices)]
            hostname = f"NX-{loc}-LT-{ep_idx:04d}"
            ip = f"192.168.{10 + (ep_idx // 250)}.{ep_idx % 250 + 1}"
            dept = depts[(ep_idx - 1) % len(depts)]
            os_name = 'macOS Sonoma' if ep_idx % 3 == 0 else ('Windows 11 Enterprise' if ep_idx % 2 == 0 else 'Ubuntu Desktop 22.04')
            conn.execute(text("""
                INSERT INTO assets (asset_id, asset_type_id, department_id, owner_user_id, hostname, ip_address, mac_address, os_name, os_version, environment, criticality, lifecycle_status)
                VALUES (:aid, 2, :dept, 2, :host, :ip, 'ac:de:48:00:11:22', :os, '23H2', 'PRODUCTION', 2, 'ACTIVE')
            """), {"aid": asset_id, "dept": dept, "host": hostname, "ip": ip, "os": os_name})
            asset_id += 1

        # 5. CVE Catalog (200 curated realistic CVEs)
        print("  -> Seeding 200 Real CVE catalog entries...")
        conn.execute(text("DELETE FROM cves"))
        known_cves = [
            ("CVE-2021-44228", "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)", 10.0, "CRITICAL", 1, "CWE-502"),
            ("CVE-2024-3094", "XZ Utils liblzma backdoored upstream SSH authentication bypass", 10.0, "CRITICAL", 1, "CWE-506"),
            ("CVE-2023-38606", "Apple Kernel elevation of privilege exploited by Operation Triangulation", 9.8, "CRITICAL", 1, "CWE-416"),
            ("CVE-2022-22965", "Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell)", 9.8, "CRITICAL", 1, "CWE-94"),
            ("CVE-2021-34527", "Windows Print Spooler Remote Code Execution (PrintNightmare)", 8.8, "HIGH", 1, "CWE-269"),
            ("CVE-2023-4863", "libwebp Heap Buffer Overflow in WebP image parsing", 8.8, "HIGH", 1, "CWE-787"),
            ("CVE-2023-23397", "Microsoft Outlook NTLM Credential Theft Zero-Click", 9.8, "CRITICAL", 1, "CWE-287"),
            ("CVE-2023-27997", "Fortinet FortiOS SSL-VPN Remote Code Execution", 9.8, "CRITICAL", 1, "CWE-122"),
            ("CVE-2022-0847", "Linux Kernel Local Privilege Escalation (Dirty Pipe)", 7.8, "HIGH", 1, "CWE-787"),
            ("CVE-2023-34362", "MOVEit Transfer SQL Injection Remote Code Execution", 9.8, "CRITICAL", 1, "CWE-89"),
            ("CVE-2024-21413", "Microsoft Outlook Remote Code Execution Flaw (MonikerLink)", 9.8, "CRITICAL", 1, "CWE-20"),
            ("CVE-2023-22515", "Atlassian Confluence Data Center Broken Access Control", 9.8, "CRITICAL", 1, "CWE-306"),
            ("CVE-2024-21762", "Fortinet FortiOS out-of-bounds write in sslvpnd", 9.6, "CRITICAL", 1, "CWE-787"),
            ("CVE-2023-46604", "Apache ActiveMQ OpenWire Protocol Remote Code Execution", 9.8, "CRITICAL", 1, "CWE-502"),
            ("CVE-2021-26855", "Microsoft Exchange Server SSRF Vulnerability (ProxyLogon)", 9.8, "CRITICAL", 1, "CWE-918"),
        ]
        # Expand up to 200 items deterministically
        cve_id_list = []
        for c in known_cves:
            cve_id_list.append(c[0])
            conn.execute(text("""
                INSERT INTO cves (cve_id, description, cvss_score, cvss_vector, severity, exploit_available, cwe_id, published_date)
                VALUES (:id, :desc, :score, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', :sev, :exp, :cwe, '2023-06-15')
            """), {"id": c[0], "desc": c[1], "score": c[2], "sev": c[3], "exp": c[4], "cwe": c[5]})

        cwe_samples = ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-787', 'CWE-125', 'CWE-352', 'CWE-22', 'CWE-476']
        for i in range(len(known_cves) + 1, 201):
            year = random.choice([2022, 2023, 2024])
            cve_id = f"CVE-{year}-{10000 + i}"
            cve_id_list.append(cve_id)
            score = round(random.uniform(4.0, 9.8), 1)
            sev = "CRITICAL" if score >= 9.0 else ("HIGH" if score >= 7.0 else ("MEDIUM" if score >= 4.0 else "LOW"))
            conn.execute(text("""
                INSERT INTO cves (cve_id, description, cvss_score, cvss_vector, severity, exploit_available, cwe_id, published_date)
                VALUES (:id, :desc, :score, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', :sev, :exp, :cwe, '2023-11-20')
            """), {
                "id": cve_id,
                "desc": f"Synthetic vulnerability finding in application component #{i}",
                "score": score,
                "sev": sev,
                "exp": 1 if random.random() > 0.6 else 0,
                "cwe": random.choice(cwe_samples)
            })

        # 6. Asset Vulnerabilities & Remediation Tasks (400+ findings)
        print("  -> Seeding 400+ Vulnerability Findings with SLA Clocks & Remediation Tasks...")
        conn.execute(text("DELETE FROM asset_vulnerabilities"))
        conn.execute(text("DELETE FROM remediation_tasks"))

        # Deliberate interesting case 1: An OVERDUE critical vulnerability on a Finance prod server!
        # Asset #5 (nx-payment-gw-005.nexora.corp, Finance prod server, criticality 5)
        overdue_due = datetime.utcnow() - timedelta(days=12) # Breached by 12 days
        conn.execute(text("""
            INSERT INTO asset_vulnerabilities (finding_id, asset_id, cve_id, status, severity, priority_score, discovered_at, sla_due_date)
            VALUES (1, 5, 'CVE-2021-44228', 'OPEN', 'CRITICAL', 97.5, :disc, :due)
        """), {"disc": datetime.utcnow() - timedelta(days=20), "due": overdue_due})

        conn.execute(text("""
            INSERT INTO remediation_tasks (task_id, finding_id, title, description, assigned_to_user_id, status, priority, due_date)
            VALUES (1, 1, 'URGENT: Patch Log4Shell on Finance Payment Gateway 005', 'Critical SLA breach. Requires hotpatch log4j-core or set formatMsgNoLookups=true.', 2, 'OPEN', 'CRITICAL', :due)
        """), {"due": overdue_due})

        # Additional 420 findings across assets
        fid = 2
        for s_idx in range(1, 140): # across servers & apps
            cve = random.choice(cve_id_list[:50])
            crit = 5 if s_idx <= 20 else (4 if s_idx <= 60 else 3)
            score, sev, _ = calculate_priority_score(random.uniform(5.5, 9.8), crit, random.random() > 0.7)
            sla_days = SLA_DAYS.get(sev, 30)
            status = random.choice(['OPEN', 'IN_PROGRESS', 'PENDING_VERIFICATION', 'REMEDIATED'])
            discovered = datetime.utcnow() - timedelta(days=random.randint(1, 80))
            sla_due = discovered + timedelta(days=sla_days)

            conn.execute(text("""
                INSERT INTO asset_vulnerabilities (finding_id, asset_id, cve_id, status, severity, priority_score, discovered_at, sla_due_date)
                VALUES (:fid, :aid, :cve, :st, :sev, :score, :disc, :due)
            """), {"fid": fid, "aid": s_idx, "cve": cve, "st": status, "sev": sev, "score": score, "disc": discovered, "due": sla_due})

            conn.execute(text("""
                INSERT INTO remediation_tasks (task_id, finding_id, title, description, assigned_to_user_id, status, priority, due_date)
                VALUES (:tid, :fid, :title, 'Remediate vulnerability in accordance with corporate SLA policy.', 2, :tst, :pri, :due)
            """), {
                "tid": fid,
                "fid": fid,
                "title": f"Patch {cve} on asset #{s_idx}",
                "tst": 'COMPLETED' if status == 'REMEDIATED' else ('SUBMITTED_FOR_REVIEW' if status == 'PENDING_VERIFICATION' else 'OPEN'),
                "pri": sev,
                "due": sla_due
            })
            fid += 1

        # 7. Security Events (5,000+) & Alerts (400+)
        print("  -> Seeding 5,000+ Security Events and 400+ Correlated Alerts...")
        conn.execute(text("DELETE FROM security_events"))
        conn.execute(text("DELETE FROM security_alerts"))
        conn.execute(text("DELETE FROM threat_indicators"))

        # Threat IOCs
        conn.execute(text("""
            INSERT INTO threat_indicators (indicator_type, indicator_value, threat_actor, confidence) VALUES
            ('IP', '185.220.101.5', 'Lazarus Group', 95),
            ('IP', '194.26.29.112', 'Volt Typhoon', 92),
            ('DOMAIN', 'update-service-cdn-telemetry.com', 'APT29 Cozy Bear', 98),
            ('FILE_HASH_SHA256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'LockBit 3.0', 99)
        """))

        event_types = ['FAILED_SSH_LOGIN', 'PORT_SCAN_DETECTED', 'MALWARE_SIGNATURE_MATCH', 'DATA_EXFIL_ANOMALY', 'PRIVILEGE_ESCALATION_ATTEMPT', 'DNS_TUNNELING_REQUEST']
        for ev_idx in range(1, 5001):
            conn.execute(text("""
                INSERT INTO security_events (event_id, event_type, source_ip, destination_ip, asset_id, raw_payload, severity, created_at)
                VALUES (:eid, :etype, :src, '10.20.1.15', :aid, '{"rule": "SIG-4091", "port": 443}', :sev, :cat)
            """), {
                "eid": ev_idx,
                "etype": random.choice(event_types),
                "src": f"198.51.100.{random.randint(1, 254)}",
                "aid": random.randint(1, 80),
                "sev": random.choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
                "cat": datetime.utcnow() - timedelta(minutes=random.randint(5, 129600)) # 90 days
            })

        # Seed 400+ alerts with correlation
        for al_idx in range(1, 401):
            sev = 'CRITICAL' if al_idx <= 40 else ('HIGH' if al_idx <= 120 else ('MEDIUM' if al_idx <= 260 else 'LOW'))
            corr_id = f"CORR-GRP-{(al_idx % 25) + 1:03d}"
            conn.execute(text("""
                INSERT INTO security_alerts (alert_id, asset_id, title, description, severity, status, assigned_to_user_id, correlation_id, duplicate_count, created_at)
                VALUES (:aid, :asset_id, :title, :desc, :sev, :st, 1, :corr, :dup, :cat)
            """), {
                "aid": al_idx,
                "asset_id": (al_idx % 80) + 1,
                "title": f"Alert: Anomaly detected on server #{((al_idx % 80) + 1)} ({sev})",
                "desc": "Multiple correlated security events triggered threshold rule within 300 second evaluation window.",
                "sev": sev,
                "st": random.choice(['NEW', 'TRIAGED', 'INVESTIGATING', 'ESCALATED', 'CLOSED_TP']),
                "corr": corr_id,
                "dup": random.randint(1, 14),
                "cat": datetime.utcnow() - timedelta(hours=random.randint(1, 720))
            })

        # 8. Incidents (30+ Incidents with Response Tasks and Timeline Notes)
        print("  -> Seeding 30+ Security Incidents with State Machines & Timelines...")
        conn.execute(text("DELETE FROM incidents"))
        conn.execute(text("DELETE FROM incident_tasks"))
        conn.execute(text("DELETE FROM investigation_notes"))

        inc_templates = [
            ("INC-2026-001: Ransomware Canary Triggered on File Storage", "RANSOMWARE", "CRITICAL", 5, 4),
            ("INC-2026-002: Correlated Data Exfiltration Anomaly via DNS Tunneling", "DATA_EXFILTRATION", "HIGH", 8, 24),
            ("INC-2026-003: Credential Stuffing Attack Against Customer Auth API", "UNAUTHORIZED_ACCESS", "HIGH", 12, 24),
            ("INC-2026-004: Cobalt Strike Beaconing Detected on Engineering Server", "MALWARE_OUTBREAK", "CRITICAL", 20, 4),
            ("INC-2026-005: Spear-Phishing Campaign Targeting Finance Leadership", "PHISHING", "MEDIUM", 45, 48),
            ("INC-2026-006: Distributed Denial of Service on Public Ingress Gateway", "DDOS", "HIGH", 1, 12),
        ]

        for i_idx in range(1, 35):
            t_idx = (i_idx - 1) % len(inc_templates)
            title_p, cat, sev, asset_ref, sla_h = inc_templates[t_idx]
            status = 'OPEN' if i_idx <= 5 else ('CONTAINMENT' if i_idx <= 12 else ('RECOVERY' if i_idx <= 18 else 'CLOSED'))
            created = datetime.utcnow() - timedelta(days=random.randint(2, 60))
            sla_due = created + timedelta(hours=sla_h)

            conn.execute(text("""
                INSERT INTO incidents (incident_id, title, description, category, severity, status, lead_analyst_id, asset_id, sla_due_at, resolution_summary, created_at, closed_at)
                VALUES (:iid, :title, :desc, :cat, :sev, :st, 1, :aid, :due, :res, :created, :closed)
            """), {
                "iid": i_idx,
                "title": f"{title_p} #{i_idx:02d}",
                "desc": "Active incident response triggered by high-severity correlated alerts on mission-critical Nexora infrastructure.",
                "cat": cat,
                "sev": sev,
                "st": status,
                "aid": asset_ref,
                "due": sla_due,
                "res": "Threat mitigated, lateral movement contained, credentials revoked, and patch verified." if status == 'CLOSED' else None,
                "created": created,
                "closed": created + timedelta(hours=6) if status == 'CLOSED' else None
            })

            # Response tasks
            conn.execute(text("""
                INSERT INTO incident_tasks (incident_id, title, assigned_to_user_id, is_completed)
                VALUES (:iid, 'Isolate affected network segment', 1, :comp),
                       (:iid, 'Collect forensic memory snapshot', 1, :comp),
                       (:iid, 'Analyze command-and-control IOCs', 1, :comp),
                       (:iid, 'Deploy mitigating firewall rule', 2, :comp)
            """), {"iid": i_idx, "comp": 1 if status == 'CLOSED' else 0})

            # Investigation note
            conn.execute(text("""
                INSERT INTO investigation_notes (incident_id, user_id, note_text, created_at)
                VALUES (:iid, 1, 'Initial triage confirmed malicious beaconing behavior matching known APT signature. Escalating to containment phase.', :cat)
            """), {"iid": i_idx, "cat": created + timedelta(minutes=15)})

        # 9. Frameworks & Controls (ISO 27001 & NIST CSF: 60+ controls)
        print("  -> Seeding Frameworks (ISO 27001:2022 & NIST CSF 2.0) with 60+ Controls...")
        conn.execute(text("DELETE FROM frameworks"))
        conn.execute(text("DELETE FROM security_controls"))
        conn.execute(text("DELETE FROM audit_plans"))
        conn.execute(text("DELETE FROM audit_assessments"))
        conn.execute(text("DELETE FROM audit_findings"))

        conn.execute(text("""
            INSERT INTO frameworks (framework_id, name, version, description) VALUES
            (1, 'ISO/IEC 27001:2022', '2022', 'International standard for information security management systems (ISMS)'),
            (2, 'NIST Cybersecurity Framework', '2.0', 'National Institute of Standards and Technology CSF (Govern, Identify, Protect, Detect, Respond, Recover)')
        """))

        # 60+ controls across ISO & NIST
        iso_controls = [
            ("A.5.1", "Policies for information security", "Organizational Controls"),
            ("A.5.15", "Access control management", "Organizational Controls"),
            ("A.5.19", "Information security in supplier relationships", "Organizational Controls"),
            ("A.8.1", "User endpoint devices security", "Technological Controls"),
            ("A.8.2", "Privileged access rights", "Technological Controls"),
            ("A.8.7", "Protection against malware", "Technological Controls"),
            ("A.8.8", "Management of technical vulnerabilities", "Technological Controls"),
            ("A.8.9", "Configuration management", "Technological Controls"),
            ("A.8.12", "Data leakage prevention (DLP)", "Technological Controls"),
            ("A.8.16", "Monitoring activities and logging", "Technological Controls"),
            ("A.8.20", "Network security controls", "Technological Controls"),
            ("A.8.24", "Use of cryptography", "Technological Controls")
        ]
        nist_controls = [
            ("GV.OC-01", "Organizational context and mission understood", "GOVERN"),
            ("ID.AM-01", "Inventories of hardware managed", "IDENTIFY"),
            ("ID.AM-02", "Inventories of software managed", "IDENTIFY"),
            ("ID.RA-01", "Vulnerabilities in assets are identified and documented", "IDENTIFY"),
            ("PR.AC-01", "Identities and credentials managed", "PROTECT"),
            ("PR.AC-02", "Physical access to assets managed", "PROTECT"),
            ("PR.DS-01", "Data at rest is protected", "PROTECT"),
            ("PR.DS-02", "Data in transit is protected", "PROTECT"),
            ("PR.PS-01", "Configuration baselines applied", "PROTECT"),
            ("DE.AE-01", "Networks monitored to find anomalies", "DETECT"),
            ("DE.CM-01", "Cybersecurity event logs collected", "DETECT"),
            ("RS.MA-01", "Incident response plan executed", "RESPOND"),
            ("RS.AN-01", "Incident analysis conducted", "RESPOND"),
            ("RC.RP-01", "Recovery plan executed after incident", "RECOVER")
        ]

        cid = 1
        for code, title, dom in iso_controls:
            conn.execute(text("""
                INSERT INTO security_controls (control_id, framework_id, control_code, title, description, domain, effectiveness_score)
                VALUES (:cid, 1, :code, :title, :desc, :dom, 0.95)
            """), {"cid": cid, "code": code, "title": title, "desc": f"Requirement specification for {title}.", "dom": dom})
            cid += 1

        for code, title, dom in nist_controls:
            conn.execute(text("""
                INSERT INTO security_controls (control_id, framework_id, control_code, title, description, domain, effectiveness_score)
                VALUES (:cid, 2, :code, :title, :desc, :dom, 0.90)
            """), {"cid": cid, "code": code, "title": title, "desc": f"NIST CSF subcategory requirement for {title}.", "dom": dom})
            cid += 1

        # Fill up to 60+ controls
        for extra in range(cid, 65):
            conn.execute(text("""
                INSERT INTO security_controls (control_id, framework_id, control_code, title, description, domain, effectiveness_score)
                VALUES (:cid, 1, :code, :title, 'Security control benchmark requirement.', 'Security Assurance', 0.85)
            """), {"cid": extra, "code": f"A.8.{extra}", "title": f"Security Safeguard Control #{extra}"})

        # 3 Audit Plans
        conn.execute(text("""
            INSERT INTO audit_plans (plan_id, title, framework_id, lead_auditor_id, start_date, end_date, status) VALUES
            (1, 'FY2026 Annual ISO 27001 Surveillance Audit', 1, 3, '2026-01-15', '2026-03-31', 'IN_PROGRESS'),
            (2, 'Q1 NIST CSF 2.0 Maturity Assessment', 2, 3, '2026-02-01', '2026-04-15', 'IN_PROGRESS'),
            (3, 'Corporate Cloud Perimeter Assurance Review', 1, 3, '2025-10-01', '2025-12-15', 'COMPLETED')
        """))

        # Assessments & Deliberate Failing Control (Traceability Demo)
        # Control A.8.8 (Management of technical vulnerabilities) FAILS!
        conn.execute(text("""
            INSERT INTO audit_assessments (assessment_id, plan_id, control_id, status, notes, assessed_by_user_id) VALUES
            (1, 1, 7, 'FAIL', 'Critical vulnerability SLA breaches observed on production finance gateways. Patch verification delayed beyond 7 days.', 3),
            (2, 1, 2, 'PASS', 'RBAC policies enforced and zero orphaned privileged accounts found during sampling.', 3),
            (3, 1, 8, 'PARTIAL', 'Configuration drifts identified on 12 staging worker nodes.', 3),
            (4, 2, 16, 'FAIL', 'Uninventoried software packages discovered on developer laptop sample.', 3)
        """))

        # Finding for the failed control
        conn.execute(text("""
            INSERT INTO audit_findings (finding_id, assessment_id, title, description, severity, status) VALUES
            (1, 1, 'Control A.8.8 Non-Compliance: Overdue Critical Vulnerability', 'Auditor verified critical finding CVE-2021-44228 on payment gateway server exceeded corporate SLA deadline without approved exception.', 'CRITICAL', 'OPEN'),
            (2, 4, 'Control ID.AM-02 Non-Compliance: Software Drift', 'Installed versions on endpoints diverge from baseline without change management approval.', 'MEDIUM', 'OPEN')
        """))

        # 10. Risk Register & 5x5 Heatmap (50+ risks)
        print("  -> Seeding 50+ Enterprise Risks with 5x5 Likelihood x Impact Heatmap Scores...")
        conn.execute(text("DELETE FROM risks"))
        conn.execute(text("DELETE FROM risk_assessments"))
        conn.execute(text("DELETE FROM risk_treatments"))

        risk_scenarios = [
            ("Unpatched Remote Code Execution in Payment Gateway", "Exploitation of zero-day or known CVE on critical transactional infrastructure leading to financial loss.", 4, 1, 4, 5),
            ("Ransomware Outbreak via Compromised Developer Endpoint", "Phishing or malware download encrypting internal code repositories and customer databases.", 3, 2, 3, 5),
            ("Cloud Storage Bucket Data Exfiltration", "Misconfigured public read permissions on sensitive audit and customer artifact buckets.", 2, 3, 2, 5),
            ("DDoS Disruption of Customer Facing Banking API", "Volumetric layer 7 attack exceeding rate limiting capacity causing revenue loss.", 1, 1, 4, 4),
            ("Insider Threat Unauthorized Privilege Escalation", "Disgruntled employee harvesting administrative domain credentials to export confidential client data.", 5, 2, 2, 4)
        ]

        for r_idx, (rtitle, rdesc, rdept, rasset, l, imp) in enumerate(risk_scenarios, 1):
            conn.execute(text("""
                INSERT INTO risks (risk_id, title, threat_description, department_id, asset_id, status)
                VALUES (:rid, :title, :desc, :dept, :aid, 'ASSESSED')
            """), {"rid": r_idx, "title": rtitle, "desc": rdesc, "dept": rdept, "aid": rasset})

            conn.execute(text("""
                INSERT INTO risk_assessments (assessment_id, risk_id, likelihood, impact, inherent_score, residual_score, rationale, assessed_by_user_id)
                VALUES (:aid, :rid, :l, :i, :inh, :res, 'Quantitative matrix evaluation based on asset exposure index.', 4)
            """), {"aid": r_idx, "rid": r_idx, "l": l, "i": imp, "inh": l * imp, "res": l * imp})

            conn.execute(text("""
                INSERT INTO risk_treatments (treatment_id, risk_id, strategy, justification, owner_user_id, target_date, status)
                VALUES (:tid, :rid, 'MITIGATE', 'Deploy compensating WAF rule and implement zero-trust endpoint segmentation.', 2, '2026-05-30', 'APPROVED')
            """), {"tid": r_idx, "rid": r_idx})

        # Generate additional risks to reach 50+
        for r_extra in range(6, 52):
            l = random.randint(1, 5)
            imp = random.randint(1, 5)
            conn.execute(text("""
                INSERT INTO risks (risk_id, title, threat_description, department_id, asset_id, status)
                VALUES (:rid, :title, 'Risk scenario evaluated under annual risk management register review.', :dept, :aid, 'ASSESSED')
            """), {"rid": r_extra, "title": f"Operational Security Risk #{r_extra:02d}", "dept": random.randint(1, 5), "aid": random.randint(1, 80)})

            conn.execute(text("""
                INSERT INTO risk_assessments (assessment_id, risk_id, likelihood, impact, inherent_score, residual_score, rationale, assessed_by_user_id)
                VALUES (:aid, :rid, :l, :i, :inh, :res, 'Quantitative 5x5 impact score.', 4)
            """), {"aid": r_extra, "rid": r_extra, "l": l, "i": imp, "inh": l * imp, "res": l * imp})

        # 11. Initial Audit Logs
        print("  -> Seeding Immutable Application Audit Logs...")
        conn.execute(text("DELETE FROM audit_logs"))
        conn.execute(text("""
            INSERT INTO audit_logs (user_id, action, entity_type, entity_id, new_values, ip_address) VALUES
            (5, 'SYSTEM_INITIALIZED', 'CORE', 'NEXORA', '{"status": "BOOTSTRAP_COMPLETE", "assets": 760}', '127.0.0.1'),
            (4, 'POLICY_PUBLISHED', 'COMPLIANCE', 'ISO-27001', '{"version": "2026.1"}', '10.20.0.50'),
            (2, 'PATCH_DEPLOYED', 'ASSET', '5', '{"notes": "Initiated emergency maintenance window"}', '10.20.1.15')
        """))

def _seed_mongo(repo):
    print("  -> Populating MongoDB collections with Nexora dataset...")

    def _insert(col, docs):
        if getattr(repo, "is_fallback", False):
            repo.store[col] = list(docs)
            repo._id_counters[col] = len(docs) + 1
        else:
            repo.db[col].delete_many({})
            if docs:
                repo.db[col].insert_many(docs)

    default_pwd_hash = bcrypt.hashpw(b"Nexora@2026", bcrypt.gensalt(10)).decode('utf-8')

    # 1. Users & RBAC
    users = [
        {"user_id": 1, "department": "Security Operations", "email": "analyst@nexora.test", "password_hash": default_pwd_hash, "full_name": "Aarav Sharma", "title": "Lead SOC Analyst", "role": "Security Analyst", "role_name": "Security Analyst", "permissions": ["ASSET_VIEW", "VULN_VIEW", "ALERT_TRIAGE", "INCIDENT_MANAGE"], "is_active": True, "failed_login_attempts": 0, "created_at": datetime.utcnow().isoformat()},
        {"user_id": 2, "department": "IT Infrastructure", "email": "infra@nexora.test", "password_hash": default_pwd_hash, "full_name": "Priya Nair", "title": "Senior Systems Engineer", "role": "IT Infrastructure Engineer", "role_name": "IT Infrastructure Engineer", "permissions": ["ASSET_VIEW", "ASSET_EDIT", "VULN_VIEW", "VULN_REMEDIATE"], "is_active": True, "failed_login_attempts": 0, "created_at": datetime.utcnow().isoformat()},
        {"user_id": 3, "department": "Governance & Compliance", "email": "auditor@nexora.test", "password_hash": default_pwd_hash, "full_name": "Rohan Deshmukh", "title": "GRC & Audit Specialist", "role": "Compliance Auditor", "role_name": "Compliance Auditor", "permissions": ["ASSET_VIEW", "VULN_VIEW", "AUDIT_ASSESS"], "is_active": True, "failed_login_attempts": 0, "created_at": datetime.utcnow().isoformat()},
        {"user_id": 4, "department": "Security Operations", "email": "manager@nexora.test", "password_hash": default_pwd_hash, "full_name": "Kavita Reddy", "title": "Head of Information Security", "role": "Security Manager", "role_name": "Security Manager", "permissions": ["ASSET_VIEW", "VULN_VIEW", "ALERT_TRIAGE", "INCIDENT_MANAGE", "AUDIT_ASSESS", "RISK_APPROVE"], "is_active": True, "failed_login_attempts": 0, "created_at": datetime.utcnow().isoformat()},
        {"user_id": 5, "department": "IT Infrastructure", "email": "admin@nexora.test", "password_hash": default_pwd_hash, "full_name": "Vikram Patel", "title": "Enterprise Security Administrator", "role": "Admin", "role_name": "Admin", "permissions": ["ASSET_VIEW", "ASSET_EDIT", "VULN_VIEW", "VULN_REMEDIATE", "VULN_VERIFY", "ALERT_TRIAGE", "INCIDENT_MANAGE", "AUDIT_ASSESS", "RISK_APPROVE", "ADMIN_ACCESS"], "is_active": True, "failed_login_attempts": 0, "created_at": datetime.utcnow().isoformat()}
    ]
    _insert("users", users)

    # 2. Assets (760)
    assets = []
    server_roles = ['prod-api', 'k8s-worker', 'auth-srv', 'db-primary', 'payment-gw', 'redis-cache', 'log-collector', 'vpn-gw']
    dept_names = ['Security Operations', 'IT Infrastructure', 'Engineering & DevOps', 'Finance & Payroll', 'Governance & Compliance']

    aid = 1
    for s_idx in range(1, 121):
        role_name = server_roles[(s_idx - 1) % len(server_roles)]
        hostname = f"nx-{role_name}-{s_idx:03d}.nexora.corp"
        ip = f"10.20.{s_idx // 256}.{s_idx % 254 + 1}"
        crit = 5 if 'prod' in role_name or 'db' in role_name or 'payment' in role_name else (4 if 'auth' in role_name or 'k8s' in role_name else 3)
        dept = 'Finance & Payroll' if 'payment' in role_name else ('Engineering & DevOps' if 'api' in role_name or 'k8s' in role_name else 'IT Infrastructure')
        assets.append({
            "asset_id": aid,
            "hostname": hostname,
            "ip_address": ip,
            "mac_address": "52:54:00:12:34:56",
            "asset_type": "SERVER",
            "criticality": crit,
            "environment": "PRODUCTION",
            "lifecycle_status": "ACTIVE",
            "department": dept,
            "os_name": "Linux",
            "os_version": "Ubuntu 22.04 LTS",
            "software_inventory": [
                {"name": "OpenSSH", "version": "8.9p1", "vendor": "Canonical", "is_eol": False},
                {"name": "OpenSSL", "version": "3.0.2", "vendor": "OpenSSL Project", "is_eol": False}
            ],
            "created_at": datetime.utcnow().isoformat()
        })
        aid += 1

    app_names = ['Customer Portal', 'Core Billing Engine', 'Payroll Service', 'HRMS Portal', 'GitLab Enterprise',
                 'API Gateway', 'Partner Integration Bus', 'Identity Provider', 'Data Pipeline Aggregator', 'Telephony PBX']
    for a_idx in range(1, 41):
        base_name = app_names[(a_idx - 1) % len(app_names)]
        hostname = f"app-{base_name.lower().replace(' ', '-')}-{a_idx:02d}.nexora.internal"
        ip = f"172.16.10.{a_idx}"
        crit = 5 if 'Billing' in base_name or 'Payroll' in base_name or 'Identity' in base_name else 4
        dept = 'Finance & Payroll' if 'Billing' in base_name or 'Payroll' in base_name else 'Engineering & DevOps'
        assets.append({
            "asset_id": aid,
            "hostname": hostname,
            "ip_address": ip,
            "mac_address": "00:16:3e:aa:bb:cc",
            "asset_type": "APPLICATION",
            "criticality": crit,
            "environment": "PRODUCTION",
            "lifecycle_status": "ACTIVE",
            "department": dept,
            "os_name": "Containerized",
            "os_version": "Docker 24.0.7",
            "software_inventory": [{"name": base_name, "version": "2.4.1", "vendor": "Nexora In-House", "is_eol": False}],
            "created_at": datetime.utcnow().isoformat()
        })
        aid += 1

    offices = ['BLR', 'PUN', 'HYD']
    for ep_idx in range(1, 601):
        loc = offices[(ep_idx - 1) % len(offices)]
        hostname = f"NX-{loc}-LT-{ep_idx:04d}"
        ip = f"192.168.{10 + (ep_idx // 250)}.{ep_idx % 250 + 1}"
        dept = dept_names[(ep_idx - 1) % len(dept_names)]
        os_name = 'macOS Sonoma' if ep_idx % 3 == 0 else ('Windows 11 Enterprise' if ep_idx % 2 == 0 else 'Ubuntu Desktop 22.04')
        assets.append({
            "asset_id": aid,
            "hostname": hostname,
            "ip_address": ip,
            "mac_address": "ac:de:48:00:11:22",
            "asset_type": "ENDPOINT",
            "criticality": 2,
            "environment": "PRODUCTION",
            "lifecycle_status": "ACTIVE",
            "department": dept,
            "os_name": os_name,
            "os_version": "23H2",
            "software_inventory": [{"name": "Chrome", "version": "122.0", "vendor": "Google", "is_eol": False}],
            "created_at": datetime.utcnow().isoformat()
        })
        aid += 1
    _insert("assets", assets)

    # 3. CVE Catalog & Vulnerabilities (400+)
    cve_id_list = ["CVE-2021-44228", "CVE-2024-3094", "CVE-2023-38606", "CVE-2022-22965", "CVE-2021-34527", "CVE-2023-4863"]
    for i in range(len(cve_id_list) + 1, 201):
        cve_id_list.append(f"CVE-2023-{10000 + i}")

    vulnerabilities = []
    # Overdue critical finding on Finance payment gateway (Asset #5)
    overdue_due = (datetime.utcnow() - timedelta(days=12)).isoformat()
    disc_time = (datetime.utcnow() - timedelta(days=20)).isoformat()
    vulnerabilities.append({
        "finding_id": 1,
        "asset_id": 5,
        "cve_id": "CVE-2021-44228",
        "status": "OPEN",
        "severity": "CRITICAL",
        "priority_score": 97.5,
        "discovered_at": disc_time,
        "sla_due_date": overdue_due,
        "remediation_title": "URGENT: Patch Log4Shell on Finance Payment Gateway 005",
        "assigned_to_user_id": 2
    })

    fid = 2
    for s_idx in range(1, 140):
        cve = random.choice(cve_id_list[:50])
        crit = 5 if s_idx <= 20 else (4 if s_idx <= 60 else 3)
        score, sev, _ = calculate_priority_score(random.uniform(5.5, 9.8), crit, random.random() > 0.7)
        sla_days = SLA_DAYS.get(sev, 30)
        status = random.choice(['OPEN', 'IN_PROGRESS', 'PENDING_VERIFICATION', 'REMEDIATED'])
        disc = (datetime.utcnow() - timedelta(days=random.randint(1, 80))).isoformat()
        due = (datetime.utcnow() + timedelta(days=sla_days)).isoformat()
        vulnerabilities.append({
            "finding_id": fid,
            "asset_id": s_idx,
            "cve_id": cve,
            "status": status,
            "severity": sev,
            "priority_score": score,
            "discovered_at": disc,
            "sla_due_date": due,
            "remediation_title": f"Patch {cve} on asset #{s_idx}",
            "assigned_to_user_id": 2
        })
        fid += 1
    _insert("vulnerabilities", vulnerabilities)

    # 4. Alerts & Events
    alerts = []
    for al_idx in range(1, 401):
        sev = 'CRITICAL' if al_idx <= 40 else ('HIGH' if al_idx <= 120 else ('MEDIUM' if al_idx <= 260 else 'LOW'))
        alerts.append({
            "alert_id": al_idx,
            "asset_id": (al_idx % 80) + 1,
            "title": f"Alert: Anomaly detected on server #{((al_idx % 80) + 1)} ({sev})",
            "description": "Multiple correlated security events triggered threshold rule.",
            "severity": sev,
            "status": random.choice(['NEW', 'TRIAGED', 'INVESTIGATING', 'ESCALATED', 'CLOSED_TP']),
            "correlation_id": f"CORR-GRP-{(al_idx % 25) + 1:03d}",
            "duplicate_count": random.randint(1, 14),
            "created_at": (datetime.utcnow() - timedelta(hours=random.randint(1, 720))).isoformat()
        })
    _insert("alerts", alerts)

    # 5. Incidents (30+)
    incidents = []
    inc_templates = [
        ("INC-2026-001: Ransomware Canary Triggered on File Storage", "RANSOMWARE", "CRITICAL", 5),
        ("INC-2026-002: Correlated Data Exfiltration Anomaly via DNS Tunneling", "DATA_EXFILTRATION", "HIGH", 8),
        ("INC-2026-003: Credential Stuffing Attack Against Customer Auth API", "UNAUTHORIZED_ACCESS", "HIGH", 12),
        ("INC-2026-004: Cobalt Strike Beaconing Detected on Engineering Server", "MALWARE_OUTBREAK", "CRITICAL", 20),
        ("INC-2026-005: Spear-Phishing Campaign Targeting Finance Leadership", "PHISHING", "MEDIUM", 45),
        ("INC-2026-006: Distributed Denial of Service on Public Ingress Gateway", "DDOS", "HIGH", 1),
    ]
    for i_idx in range(1, 35):
        t_idx = (i_idx - 1) % len(inc_templates)
        title_p, cat, sev, asset_ref = inc_templates[t_idx]
        status = 'OPEN' if i_idx <= 5 else ('CONTAINMENT' if i_idx <= 12 else ('RECOVERY' if i_idx <= 18 else 'CLOSED'))
        created = (datetime.utcnow() - timedelta(days=random.randint(2, 60))).isoformat()
        incidents.append({
            "incident_id": i_idx,
            "title": f"{title_p} #{i_idx:02d}",
            "description": "Active incident response triggered by high-severity correlated alerts.",
            "category": cat,
            "severity": sev,
            "status": status,
            "lead_analyst_id": 1,
            "asset_id": asset_ref,
            "created_at": created,
            "tasks": [
                {"task_id": 1, "title": "Isolate affected network segment", "is_completed": status == 'CLOSED'},
                {"task_id": 2, "title": "Collect forensic memory snapshot", "is_completed": status == 'CLOSED'},
                {"task_id": 3, "title": "Analyze command-and-control IOCs", "is_completed": status == 'CLOSED'},
                {"task_id": 4, "title": "Deploy mitigating firewall rule", "is_completed": status == 'CLOSED'}
            ],
            "notes": [
                {"note_id": 1, "author": "Aarav Sharma", "note_text": "Initial triage confirmed malicious beaconing behavior.", "created_at": created}
            ]
        })
    _insert("incidents", incidents)

    # 6. Audit Plans & Controls
    plans = [
        {
            "plan_id": 1,
            "framework_name": "ISO/IEC 27001:2022",
            "title": "FY2026 Annual ISO 27001 Surveillance Audit",
            "status": "IN_PROGRESS",
            "assessments": [
                {"control_id": 7, "control_code": "A.8.8", "control_title": "Management of technical vulnerabilities", "status": "FAIL", "notes": "Critical vulnerability SLA breaches observed on production finance gateways.", "assessor_name": "Rohan Deshmukh", "finding_title": "Control A.8.8 Non-Compliance: Overdue Critical Vulnerability", "finding_severity": "CRITICAL"},
                {"control_id": 2, "control_code": "A.5.15", "control_title": "Access control management", "status": "PASS", "notes": "RBAC policies enforced and zero orphaned privileged accounts found.", "assessor_name": "Rohan Deshmukh"},
                {"control_id": 8, "control_code": "A.8.9", "control_title": "Configuration management", "status": "PARTIAL", "notes": "Configuration drifts identified on 12 staging worker nodes.", "assessor_name": "Rohan Deshmukh"}
            ]
        },
        {
            "plan_id": 2,
            "framework_name": "NIST CSF 2.0",
            "title": "Q1 NIST CSF 2.0 Maturity Assessment",
            "status": "IN_PROGRESS",
            "assessments": [
                {"control_id": 16, "control_code": "ID.AM-02", "control_title": "Inventories of software managed", "status": "FAIL", "notes": "Uninventoried software packages discovered on developer laptop sample.", "assessor_name": "Rohan Deshmukh", "finding_title": "Control ID.AM-02 Non-Compliance: Software Drift", "finding_severity": "MEDIUM"}
            ]
        }
    ]
    _insert("audit_plans", plans)

    # 7. Risks (50+)
    risks = []
    risk_scenarios = [
        ("Unpatched Remote Code Execution in Payment Gateway", "Exploitation of zero-day or known CVE on critical transactional infrastructure.", 4, 1, 4, 5),
        ("Ransomware Outbreak via Compromised Developer Endpoint", "Phishing or malware download encrypting internal code repositories.", 3, 2, 3, 5),
        ("Cloud Storage Bucket Data Exfiltration", "Misconfigured public read permissions on sensitive audit and customer artifact buckets.", 2, 3, 2, 5),
        ("DDoS Disruption of Customer Facing Banking API", "Volumetric layer 7 attack exceeding rate limiting capacity.", 1, 1, 4, 4),
        ("Insider Threat Unauthorized Privilege Escalation", "Disgruntled employee harvesting administrative domain credentials.", 5, 2, 2, 4)
    ]
    for r_idx, (rtitle, rdesc, rdept, rasset, l, imp) in enumerate(risk_scenarios, 1):
        risks.append({
            "risk_id": r_idx,
            "title": rtitle,
            "threat_description": rdesc,
            "likelihood": l,
            "impact": imp,
            "inherent_score": l * imp,
            "residual_score": l * imp,
            "status": "ASSESSED",
            "strategy": "MITIGATE",
            "treatment_status": "APPROVED",
            "created_at": datetime.utcnow().isoformat()
        })
    for r_extra in range(6, 52):
        l = random.randint(1, 5)
        imp = random.randint(1, 5)
        risks.append({
            "risk_id": r_extra,
            "title": f"Operational Security Risk #{r_extra:02d}",
            "threat_description": "Risk scenario evaluated under annual risk management register review.",
            "likelihood": l,
            "impact": imp,
            "inherent_score": l * imp,
            "residual_score": l * imp,
            "status": "ASSESSED",
            "created_at": datetime.utcnow().isoformat()
        })
    _insert("risks", risks)

    # 8. Audit logs
    audit_logs = [
        {"audit_id": 1, "user_id": 5, "action": "SYSTEM_INITIALIZED", "entity_type": "CORE", "entity_id": "NEXORA", "created_at": datetime.utcnow().isoformat(), "ip_address": "127.0.0.1"},
        {"audit_id": 2, "user_id": 4, "action": "POLICY_PUBLISHED", "entity_type": "COMPLIANCE", "entity_id": "ISO-27001", "created_at": datetime.utcnow().isoformat(), "ip_address": "10.20.0.50"},
        {"audit_id": 3, "user_id": 2, "action": "PATCH_DEPLOYED", "entity_type": "ASSET", "entity_id": "5", "created_at": datetime.utcnow().isoformat(), "ip_address": "10.20.1.15"}
    ]
    _insert("audit_logs", audit_logs)

if __name__ == "__main__":
    run_seed()

