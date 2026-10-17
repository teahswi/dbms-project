"""
Repository Parity Tests
Verifies that relational (SQLite/MySQL) and document (MongoDB) engines implement
identical interfaces, calculate identical metrics, and store equivalent records.
"""
import pytest
from app.repositories.base import BaseRepository
from app.repositories.mysql_repo import MySQLRepository
from app.repositories.mongo_repo import MongoRepository
from app.seeds.seed_data import _seed_sql, _seed_mongo

@pytest.fixture(scope="module")
def seeded_repositories():
    # 1. Relational in-memory repository
    r_sql = MySQLRepository(use_sqlite=True, sqlite_path=":memory:", fallback=False)
    _seed_sql(r_sql)

    # 2. Document in-memory repository
    r_mongo = MongoRepository(fallback=True)
    _seed_mongo(r_mongo)

    return r_sql, r_mongo

def test_interface_compliance():
    # Both implementations must inherit from BaseRepository
    assert issubclass(MySQLRepository, BaseRepository)
    assert issubclass(MongoRepository, BaseRepository)

def test_asset_count_parity(seeded_repositories):
    r_sql, r_mongo = seeded_repositories
    assets_sql = r_sql.list_assets()
    assets_mongo = r_mongo.list_assets()
    assert len(assets_sql) == 760
    assert len(assets_mongo) == 760

def test_vulnerability_counts_and_overdue_finding(seeded_repositories):
    r_sql, r_mongo = seeded_repositories
    vulns_sql = r_sql.list_vulnerabilities()
    vulns_mongo = r_mongo.list_vulnerabilities()
    assert len(vulns_sql) >= 100
    assert len(vulns_mongo) >= 100
    assert len(vulns_sql) == len(vulns_mongo)


    # Overdue critical finding on Asset #5 (Finance payment gateway)
    v1_sql = r_sql.get_vulnerability_by_id(1)
    v1_mongo = r_mongo.get_vulnerability_by_id(1)
    assert v1_sql["cve_id"] == "CVE-2021-44228"
    assert v1_mongo["cve_id"] == "CVE-2021-44228"
    assert v1_sql["severity"] == "CRITICAL"
    assert v1_mongo["severity"] == "CRITICAL"

def test_incident_count_parity(seeded_repositories):
    r_sql, r_mongo = seeded_repositories
    inc_sql = r_sql.list_incidents()
    inc_mongo = r_mongo.list_incidents()
    assert len(inc_sql) == 34
    assert len(inc_mongo) == 34

def test_compliance_and_controls_parity(seeded_repositories):
    r_sql, r_mongo = seeded_repositories
    frameworks_sql = r_sql.list_frameworks()
    frameworks_mongo = r_mongo.list_frameworks()
    assert len(frameworks_sql) == 2
    assert len(frameworks_mongo) == 2

    plans_sql = r_sql.list_audit_plans()
    plans_mongo = r_mongo.list_audit_plans()
    assert len(plans_sql) >= 2
    assert len(plans_mongo) >= 2

def test_risk_heatmap_parity(seeded_repositories):
    r_sql, r_mongo = seeded_repositories
    heat_sql = r_sql.get_risk_heatmap()
    heat_mongo = r_mongo.get_risk_heatmap()
    assert len(heat_sql) == 25  # 5x5 grid
    assert len(heat_mongo) == 25
    assert sum(c["count"] for c in heat_sql) > 40
    assert sum(c["count"] for c in heat_mongo) > 40

def test_executive_posture_structure_parity(seeded_repositories):
    r_sql, r_mongo = seeded_repositories
    p_sql = r_sql.get_executive_posture()
    p_mongo = r_mongo.get_executive_posture()

    expected_keys = {
        "posture_score", "asset_count", "open_vulnerabilities",
        "critical_vulnerabilities", "high_vulnerabilities", "medium_vulnerabilities", "low_vulnerabilities",
        "active_alerts", "open_incidents", "failed_controls", "high_risks",
        "mean_time_to_detect_minutes", "mean_time_to_remediate_hours",
        "department_exposure", "aging_funnel", "backend_info"
    }

    assert expected_keys.issubset(set(p_sql.keys()))
    assert expected_keys.issubset(set(p_mongo.keys()))
    assert p_sql["asset_count"] == p_mongo["asset_count"] == 760
    assert p_sql["open_incidents"] == p_mongo["open_incidents"] == 18
    assert p_sql["failed_controls"] == p_mongo["failed_controls"] == 2
