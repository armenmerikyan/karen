import sqlite3

# Connect to both databases
source_conn = sqlite3.connect("db.sqlite3.bak")
dest_conn = sqlite3.connect("db.sqlite3")

source_cursor = source_conn.cursor()
dest_cursor = dest_conn.cursor()

# Get all table names except django_migrations
source_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [table[0] for table in source_cursor.fetchall() if table[0] != "django_migrations"]

for table_name in tables:
    # Fetch all data from the backup table
    source_cursor.execute(f"SELECT * FROM {table_name}")
    rows = source_cursor.fetchall()
    
    if rows:
        # Construct dynamic insert query
        placeholders = ",".join(["?"] * len(rows[0]))
        query = f"INSERT OR IGNORE INTO {table_name} VALUES ({placeholders})"
        
        # Insert data into the new database
        dest_cursor.executemany(query, rows)
        dest_conn.commit()

# Close connections
source_conn.close()
dest_conn.close()

print("Data restored successfully, skipping django_migrations!")
