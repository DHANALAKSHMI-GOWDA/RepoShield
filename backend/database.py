
import sqlite3
import json
from pathlib import Path
from datetime import datetime

# Database file will be created in the main RepoShield folder
BASE_DIR = Path(__file__).resolve().parent.parent
DB_DIR = BASE_DIR / "data"
DB_DIR.mkdir(exist_ok=True)
DB_PATH = DB_DIR / "reposhield.db"

def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository_name TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            security_score INTEGER,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            findings TEXT,
            status TEXT DEFAULT 'completed'
        )
    """)

    connection.commit()
    connection.close()


def save_scan(repository_name, security_score, findings):
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for finding in findings:
        severity = finding.get("severity", "").capitalize()

        if severity in counts:
            counts[severity] += 1

    connection = get_connection()

    cursor = connection.execute("""
        INSERT INTO scans (
            repository_name,
            scan_date,
            security_score,
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            findings
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        repository_name,
        datetime.now().isoformat(timespec="seconds"),
        security_score,
        len(findings),
        counts["Critical"],
        counts["High"],
        counts["Medium"],
        counts["Low"],
        json.dumps(findings)
    ))

    scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return scan_id


def get_scan_history():
    connection = get_connection()

    rows = connection.execute("""
        SELECT * FROM scans
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    connection = get_connection()

    row = connection.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()

    connection.close()

    if row is None:
        return None

    result = dict(row)
    result["findings"] = json.loads(result["findings"] or "[]")

    return result
