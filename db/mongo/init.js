/**
 * CYBERSHIELD: MongoDB Database Initialization Script
 * Engine: MongoDB 6.0+ / 7.0+
 * Architectural pattern: Embedded sub-documents for read-heavy & high-cohesion entities,
 * normalized references for shared entities, compound indexes, and $jsonSchema validation.
 */

db = db.getSiblingDB('cybershield');

// Drop existing collections to ensure idempotent seeding
db.users.drop();
db.assets.drop();
db.cves.drop();
db.vulnerabilities.drop();
db.remediations.drop();
db.security_events.drop();
db.alerts.drop();
db.incidents.drop();
db.controls.drop();
db.audits.drop();
db.risks.drop();
db.audit_logs.drop();

// ----------------------------------------------------------------------------
// 1. USERS & RBAC COLLECTION ($jsonSchema Validation)
// ----------------------------------------------------------------------------
db.createCollection('users', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['email', 'password_hash', 'full_name', 'role', 'department'],
      properties: {
        email: { bsonType: 'string', pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$' },
        password_hash: { bsonType: 'string' },
        full_name: { bsonType: 'string' },
        title: { bsonType: 'string' },
        role: { enum: ['Security Analyst', 'IT Infrastructure Engineer', 'Compliance Auditor', 'Security Manager', 'Admin'] },
        department: { bsonType: 'string' },
        permissions: { bsonType: 'array', items: { bsonType: 'string' } },
        is_active: { bsonType: 'bool' },
        failed_login_attempts: { bsonType: 'int', minimum: 0 },
        lockout_until: { bsonType: ['date', 'null'] },
        created_at: { bsonType: 'date' }
      }
    }
  }
});
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ role: 1 });
db.users.createIndex({ department: 1 });

// ----------------------------------------------------------------------------
// 2. ASSETS COLLECTION (Embedded Software Inventory)
// ----------------------------------------------------------------------------
db.createCollection('assets', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['hostname', 'ip_address', 'asset_type', 'criticality', 'environment', 'lifecycle_status'],
      properties: {
        hostname: { bsonType: 'string' },
        ip_address: { bsonType: 'string' },
        asset_type: { enum: ['SERVER', 'ENDPOINT', 'APPLICATION', 'DATABASE', 'CLOUD_RESOURCE', 'NETWORK_DEVICE'] },
        criticality: { bsonType: 'int', minimum: 1, maximum: 5 },
        environment: { enum: ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'DISASTER_RECOVERY'] },
        lifecycle_status: { enum: ['ACTIVE', 'MAINTENANCE', 'DECOMMISSIONED', 'PROVISIONING'] },
        department: { bsonType: 'string' },
        owner_email: { bsonType: 'string' },
        os_name: { bsonType: 'string' },
        os_version: { bsonType: 'string' },
        software_inventory: {
          bsonType: 'array',
          items: {
            bsonType: 'object',
            required: ['name', 'version', 'vendor'],
            properties: {
              name: { bsonType: 'string' },
              version: { bsonType: 'string' },
              vendor: { bsonType: 'string' },
              is_eol: { bsonType: 'bool' }
            }
          }
        },
        calculated_exposure_score: { bsonType: 'number' },
        created_at: { bsonType: 'date' }
      }
    }
  }
});
db.assets.createIndex({ hostname: 1 }, { unique: true });
db.assets.createIndex({ ip_address: 1 });
db.assets.createIndex({ criticality: -1, environment: 1 });
db.assets.createIndex({ 'software_inventory.name': 1 });

// ----------------------------------------------------------------------------
// 3. VULNERABILITIES & REMEDIATION (Referenced & Embedded Tasks)
// ----------------------------------------------------------------------------
db.createCollection('vulnerabilities', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['cve_id', 'asset_id', 'severity', 'status', 'sla_due_date'],
      properties: {
        cve_id: { bsonType: 'string' },
        asset_id: { bsonType: 'string' },
        asset_hostname: { bsonType: 'string' },
        cvss_score: { bsonType: 'number', minimum: 0.0, maximum: 10.0 },
        severity: { enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
        priority_score: { bsonType: 'number' },
        status: { enum: ['OPEN', 'IN_PROGRESS', 'PENDING_VERIFICATION', 'REMEDIATED', 'RISK_ACCEPTED', 'FALSE_POSITIVE'] },
        sla_due_date: { bsonType: 'date' },
        remediation_task: {
          bsonType: 'object',
          properties: {
            title: { bsonType: 'string' },
            assigned_to: { bsonType: 'string' },
            status: { enum: ['OPEN', 'IN_PROGRESS', 'SUBMITTED_FOR_REVIEW', 'COMPLETED', 'BLOCKED'] },
            due_date: { bsonType: 'date' },
            fix_notes: { bsonType: 'string' },
            completed_at: { bsonType: ['date', 'null'] }
          }
        },
        verification: {
          bsonType: 'object',
          properties: {
            verified_by: { bsonType: 'string' },
            notes: { bsonType: 'string' },
            verified_at: { bsonType: 'date' }
          }
        }
      }
    }
  }
});
db.vulnerabilities.createIndex({ asset_id: 1, cve_id: 1 }, { unique: true });
db.vulnerabilities.createIndex({ status: 1, priority_score: -1 });
db.vulnerabilities.createIndex({ sla_due_date: 1 });

// ----------------------------------------------------------------------------
// 4. HIGH-VELOCITY SECURITY EVENTS (TTL Index: 90 days retention)
// ----------------------------------------------------------------------------
db.createCollection('security_events');
db.security_events.createIndex({ created_at: 1 }, { expireAfterSeconds: 7776000 }); // 90 days TTL
db.security_events.createIndex({ source_ip: 1, event_type: 1 });
db.security_events.createIndex({ asset_id: 1, severity: 1 });

// ----------------------------------------------------------------------------
// 5. SECURITY ALERTS
// ----------------------------------------------------------------------------
db.createCollection('alerts');
db.alerts.createIndex({ asset_id: 1, status: 1 });
db.alerts.createIndex({ correlation_id: 1 });
db.alerts.createIndex({ severity: 1, created_at: -1 });

// ----------------------------------------------------------------------------
// 6. INCIDENTS (Embedded Timeline, Response Tasks, Investigation Notes)
// ----------------------------------------------------------------------------
db.createCollection('incidents', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['title', 'category', 'severity', 'status', 'sla_due_at'],
      properties: {
        title: { bsonType: 'string' },
        category: { bsonType: 'string' },
        severity: { enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
        status: { enum: ['OPEN', 'TRIAGE', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'CLOSED'] },
        lead_analyst: { bsonType: 'string' },
        asset_id: { bsonType: 'string' },
        linked_alert_ids: { bsonType: 'array', items: { bsonType: 'string' } },
        tasks: {
          bsonType: 'array',
          items: {
            bsonType: 'object',
            required: ['title', 'is_completed'],
            properties: {
              task_id: { bsonType: 'string' },
              title: { bsonType: 'string' },
              assigned_to: { bsonType: 'string' },
              is_completed: { bsonType: 'bool' },
              completed_at: { bsonType: ['date', 'null'] }
            }
          }
        },
        investigation_notes: {
          bsonType: 'array',
          items: {
            bsonType: 'object',
            required: ['author', 'note_text', 'timestamp'],
            properties: {
              author: { bsonType: 'string' },
              note_text: { bsonType: 'string' },
              timestamp: { bsonType: 'date' }
            }
          }
        },
        mttd_seconds: { bsonType: ['int', 'null'] },
        mttr_seconds: { bsonType: ['int', 'null'] },
        sla_due_at: { bsonType: 'date' },
        resolution_summary: { bsonType: ['string', 'null'] },
        created_at: { bsonType: 'date' },
        closed_at: { bsonType: ['date', 'null'] }
      }
    }
  }
});
db.incidents.createIndex({ status: 1, severity: 1 });
db.incidents.createIndex({ lead_analyst: 1 });
db.incidents.createIndex({ asset_id: 1 });

// ----------------------------------------------------------------------------
// 7. COMPLIANCE, RISKS & AUDIT LOGS
// ----------------------------------------------------------------------------
db.createCollection('controls');
db.controls.createIndex({ framework: 1, control_code: 1 }, { unique: true });
db.controls.createIndex({ domain: 1 });

db.createCollection('audits');
db.audits.createIndex({ status: 1, framework: 1 });

db.createCollection('risks');
db.risks.createIndex({ status: 1, 'residual_score': -1 });

db.createCollection('audit_logs');
db.audit_logs.createIndex({ created_at: -1 });
db.audit_logs.createIndex({ entity_type: 1, entity_id: 1 });
db.audit_logs.createIndex({ user_email: 1 });

print("CyberShield MongoDB collections, indexes, and $jsonSchema validations configured successfully.");
