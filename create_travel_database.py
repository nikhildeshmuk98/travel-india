import os
import ssl
import pymysql
from pathlib import Path

ctx = ssl.create_default_context(cafile=str(Path("aiven-ca.pem").resolve()))

conn = pymysql.connect(
    host="mysql-38102cfc-nikhildeshmuk98-9c58.i.aivencloud.com",
    port=24029,
    user="travelapp",
    password=os.environ["AIVEN_DB_PASSWORD"],
    ssl=ctx,
    charset="utf8mb4",
    autocommit=True
)

try:
    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA "
            "WHERE SCHEMA_NAME = 'travel_india'"
        )

        if cursor.fetchone():
            print("Database travel_india already exists.")
            print("No changes made.")
        else:
            cursor.execute(
                "CREATE DATABASE travel_india "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            print("SUCCESS! travel_india database created.")

        cursor.execute("SHOW DATABASES")
        print("\nAvailable databases:")
        for row in cursor.fetchall():
            print("-", row[0])
finally:
    conn.close()
