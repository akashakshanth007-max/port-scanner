import sqlite3

DB_NAME = "scanner.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            scan_duration REAL,
            results TEXT
        )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("SQLite database created successfully.")