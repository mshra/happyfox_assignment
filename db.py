import sqlite3
from typing import Optional

conn = sqlite3.connect("db.db")
cur = conn.cursor()
cur.execute("""CREATE TABLE IF NOT EXISTS emails(
    msg_id VARCHAR(255) PRIMARY KEY,
    subject VARCHAR(255),
    from_email VARCHAR(255),
    date VARCHAR(50),
    snippet TEXT
)""")

def insert(msg_id: str, subject: str, from_email: str, date: str, snippet: str):
    cur.execute("SELECT 1 FROM emails WHERE msg_id = ?", (msg_id,))
    exists = cur.fetchone()
    if not exists:
        cur.execute(
            "INSERT INTO emails (msg_id, subject, from_email, date, snippet) VALUES (?, ?, ?, ?, ?)",
            (msg_id, subject, from_email, date, snippet)
        )
        conn.commit()

def get(msg_id: Optional[str] = None):
    if msg_id is None:
        return cur.execute("SELECT * FROM emails").fetchall()
    else:
        return cur.execute(
            "SELECT * FROM emails WHERE msg_id = ?",
            (msg_id,)
        ).fetchone()
