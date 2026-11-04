
import sqlite3
import pandas as pd
from datetime import datetime

DB_NAME = "toolkit_telemetry.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            module_name TEXT,
            model_used TEXT,
            input_summary TEXT,
            result_status TEXT,
            latency_sec REAL
        )
    """)
    conn.commit()
    conn.close()

def log_event(module_name, model_used, input_summary, result_status, latency_sec):
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO telemetry_logs (timestamp, module_name, model_used, input_summary, result_status, latency_sec)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), module_name, model_used, input_summary, result_status, latency_sec))
    conn.commit()
    conn.close()

def get_logs_dataframe():
    init_db()
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM telemetry_logs ORDER BY id DESC", conn)
    conn.close()
    return df

