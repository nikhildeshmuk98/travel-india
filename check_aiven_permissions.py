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
    charset="utf8mb4"
)

try:
    with conn.cursor() as cursor:
        cursor.execute("SHOW GRANTS FOR CURRENT_USER()")
        print("TRAVELAPP PERMISSIONS:")
        for row in cursor.fetchall():
            print(row[0])
finally:
    conn.close()
