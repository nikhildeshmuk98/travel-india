import pymysql
import ssl
import os
from pathlib import Path

HOST = "mysql-38102cfc-nikhildeshmuk98-9c58.i.aivencloud.com"
PORT = 24029
USER = "travelapp"

ca_path = Path("aiven-ca.pem").resolve()

if not ca_path.exists():
    print("ERROR: Aiven certificate not found.")
    raise SystemExit(1)

password = os.environ["AIVEN_DB_PASSWORD"]

ssl_context = ssl.create_default_context(cafile=str(ca_path))
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED

try:
    connection = pymysql.connect(
        host=HOST,
        port=PORT,
        user=USER,
        password=password,
        ssl=ssl_context,
        charset="utf8mb4",
        connect_timeout=20,
        autocommit=True
    )

    with connection.cursor() as cursor:
        cursor.execute("SELECT VERSION(), CURRENT_USER()")
        result = cursor.fetchone()

        print("\nSUCCESS! Aiven connection established.")
        print("MySQL Version:", result[0])
        print("Connected User:", result[1])

        cursor.execute("SHOW DATABASES")
        print("\nAccessible databases:")
        for row in cursor.fetchall():
            print("-", row[0])

    connection.close()

except Exception as error:
    print("\nAiven connection failed.")
    print("Error:", error)
