import os
import re
import ssl
import pymysql
import sqlparse
from pathlib import Path

HOST = "mysql-38102cfc-nikhildeshmuk98-9c58.i.aivencloud.com"
PORT = 24029
USER = "travelapp"
DATABASE = "travel_india"

backup = Path("travel_india_backup_utf8.sql")
ca_file = Path("aiven-ca.pem")

if not backup.exists() or not ca_file.exists():
    raise SystemExit("ERROR: Backup or CA certificate is missing.")

sql = backup.read_text(encoding="utf-8")
raw_statements = sqlparse.split(sql)

def remove_normal_comments(statement):
    statement = re.sub(r"(?m)^\s*--.*$", "", statement)
    statement = re.sub(r"(?m)^\s*#.*$", "", statement)
    statement = re.sub(r"/\*(?!\!).*?\*/", "", statement, flags=re.S)
    return statement.strip()

statements = [
    raw.strip()
    for raw in raw_statements
    if remove_normal_comments(raw)
]

create_count = sum(
    bool(re.match(r"CREATE\s+TABLE\b", remove_normal_comments(s), re.I))
    for s in statements
)

drop_count = sum(
    bool(re.match(r"DROP\s+TABLE\b", remove_normal_comments(s), re.I))
    for s in statements
)

if create_count != 10 or drop_count != 10:
    raise SystemExit(
        f"STOP: Expected 10 CREATE and 10 DROP statements. "
        f"Found {create_count} CREATE and {drop_count} DROP."
    )

if any(
    re.match(r"(CREATE|DROP)\s+DATABASE\b", remove_normal_comments(s), re.I)
    for s in statements
):
    raise SystemExit("STOP: Database creation/deletion statements found.")

ssl_context = ssl.create_default_context(cafile=str(ca_file.resolve()))

connection = pymysql.connect(
    host=HOST,
    port=PORT,
    user=USER,
    password=os.environ["AIVEN_DB_PASSWORD"],
    database=DATABASE,
    ssl=ssl_context,
    charset="utf8mb4",
    connect_timeout=20,
    autocommit=True
)

try:
    with connection.cursor() as cursor:
        cursor.execute("SHOW TABLES")
        existing = cursor.fetchall()

        if existing:
            print("STOP: Target database is not empty.")
            print("No import performed.")
            raise SystemExit(1)

        print("Target database is empty.")
        print("Starting import of 10 tables...\n")

        for index, statement in enumerate(statements, start=1):
            try:
                cursor.execute(statement)

                clean = remove_normal_comments(statement)

                if re.match(r"CREATE\s+TABLE\b", clean, re.I):
                    print(f"Table created: {clean[:100]}")

                elif re.match(r"INSERT\s+INTO\b", clean, re.I):
                    print(f"Data inserted: statement {index}")

            except Exception as error:
                print(f"\nIMPORT FAILED at statement {index}")
                print("Error:", error)
                print("Do not rerun the import automatically.")
                raise

        cursor.execute("SHOW TABLES")
        tables = [row[0] for row in cursor.fetchall()]

        print("\nIMPORT COMPLETED!")
        print("Tables imported:", len(tables))

        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
            count = cursor.fetchone()[0]
            print(f"- {table}: {count} rows")

finally:
    connection.close()
