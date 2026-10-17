# Architectural Decisions & Design Rationale (decisions.md)

This document tracks all key technical and architectural decisions made for **CyberShield** (Enterprise Cybersecurity Risk and Operations Management System) for Nexora Technologies.

---

## 1. Multi-Database Architecture & Repository Pattern
- **Decision:** Implement a clean Repository Pattern with an abstract interface (`BaseRepository`) and two interchangeable implementations:
  - `MySQLRepository`: Uses SQLAlchemy Core & Object Relational mappings with parameterized SQL, 3NF normalized schema (24 tables), native transactions, stored procedures, triggers, views, and index optimization.
  - `MongoRepository`: Uses PyMongo with schema validation (`$jsonSchema`), compound indexes, aggregation pipelines, and embedded subdocuments for high-velocity and nested query patterns (e.g. event streams, incident timelines).
  - Standalone/Fallback Support: In local development environments without running MySQL or MongoDB daemons, `MySQLRepository` gracefully supports SQLite with compatible SQL syntax or connects to configured MySQL instances; `MongoRepository` supports PyMongo with mongomock fallback. This ensures the demo and test suites execute deterministically anywhere.
- **Rationale:** Meets the rigorous dual-DBMS academic requirements while preserving strict production SaaS standards. Switching between backends requires only setting `DB_BACKEND=mysql` or `DB_BACKEND=mongo`.

---

## 2. Shared Business Logic & Service Layer
- **Decision:** All business rules, risk priority calculations, SLA thresholds, role-based access checks, and status machine transitions reside exclusively in the `/services/` layer.
- **Rationale:** Ensures both MySQL and MongoDB backends behave 100% identically for all REST API consumers and end users.

---

## 3. Risk Priority Scoring Formula
- **Decision:** The transparent priority score is calculated as:
  $$\text{Priority} = \min\left(100, (\text{CVSS} \times 10) \times W_{\text{asset}} \times M_{\text{exploit}} \times (1 - E_{\text{control}})\right)$$
  Where:
  - $\text{CVSS}$: 0.0 – 10.0
  - $W_{\text{asset}}$ (Asset Criticality Weight): Tier 1 (Critical) = 1.3, Tier 2 (High) = 1.15, Tier 3 (Medium) = 1.0, Tier 4 (Low) = 0.85, Tier 5 (Info) = 0.7
  - $M_{\text{exploit}}$ (Exploit Multiplier): Known exploited / active weaponized exploit = 1.25, PoC available = 1.1, None = 1.0
  - $E_{\text{control}}$ (Control Effectiveness): Active mitigating controls = 0.0 to 0.4 reduction factor.
  - Buckets: Critical ($\ge 80$), High ($60 - 79.9$), Medium ($35 - 59.9$), Low ($< 35$).
- **Rationale:** Every score input is stored alongside the computed value for explainability and auditing in the UI.

---

## 4. Security & Audit Logging Policy
- **Decision:** Application audit logs (`audit_logs`) are strictly append-only. There are zero update or delete endpoints exposed in the API or repository.
- **Rationale:** Prevents tampering by any user (including admins) and satisfies SOC 2, ISO 27001, and NIST CSF compliance mandates.

---

## 5. UI/UX Paradigm
- **Decision:** Dark mode default using deep slate/navy `#0b0f19` and `#111827`, with electric cyan `#06b6d4` and indigo `#6366f1` accents. Strict semantic severity color coding across all badges, graphs, and tables:
  - Critical: Crimson / Rose (`#ef4444`)
  - High: Deep Orange (`#f97316`)
  - Medium: Amber / Yellow (`#f59e0b`)
  - Low: Sky Blue (`#0ea5e9`)
  - Info: Slate / Cool Grey (`#64748b`)
- **Rationale:** Matches modern Tier-1 SOC platforms (CrowdStrike Falcon, SentinelOne, Palo Alto Cortex) for high information density and minimal eye fatigue.
