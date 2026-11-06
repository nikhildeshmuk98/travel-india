
import requests
import mysql.connector
import re


# =====================================================
# 1. DATABASE CONFIGURATION
# =====================================================

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "",  # Enter your actual MySQL password
    "database": "india_tourism_db"
}


# =====================================================
# 2. LGD API CONFIGURATION
# =====================================================

API_BASE = "https://india-lgd-index-api.vercel.app/v1"


# =====================================================
# 3. STATE NAME NORMALIZATION
# =====================================================

def normalize_name(state_name):

    state_name = state_name.upper().replace("&", " AND ")

    state_name = re.sub(
        r"[^A-Z0-9 ]",
        " ",
        state_name
    )

    state_name = re.sub(
        r"\s+",
        " ",
        state_name
    ).strip()

    aliases = {

        "NCT OF DELHI": "DELHI",

        "NATIONAL CAPITAL TERRITORY OF DELHI": "DELHI",

        "THE DADRA AND NAGAR HAVELI AND DAMAN AND DIU":
            "DADRA AND NAGAR HAVELI AND DAMAN AND DIU",

        "ORISSA": "ODISHA",

        "UTTARANCHAL": "UTTARAKHAND",

        "PONDICHERRY": "PUDUCHERRY"
    }

    return aliases.get(state_name, state_name)


# =====================================================
# 4. FETCH DATA FROM LGD API
# =====================================================

def fetch_api_data(endpoint):

    url = f"{API_BASE}/{endpoint}"

    print(f"\nRequesting: {url}")

    response = requests.get(
        url,
        timeout=60
    )

    response.raise_for_status()

    result = response.json()

    if not result.get("success"):

        raise Exception(
            f"API returned unsuccessful response: {result}"
        )

    data = result.get("data")

    if not isinstance(data, list):

        raise Exception(
            f"Unexpected API response for {endpoint}"
        )

    return data


# =====================================================
# 5. MAIN IMPORT FUNCTION
# =====================================================

def main():

    connection = None
    cursor = None

    try:

        # ---------------------------------------------
        # CONNECT TO MYSQL
        # ---------------------------------------------

        print("\nConnecting to MySQL...")

        connection = mysql.connector.connect(
            **DB_CONFIG
        )

        cursor = connection.cursor(
            dictionary=True
        )

        print("MySQL connection successful!")


        # ---------------------------------------------
        # FETCH EXISTING DATABASE STATES
        # ---------------------------------------------

        print("\nReading states from database...")

        cursor.execute("""
            SELECT id, state_name
            FROM states
        """)

        db_states = cursor.fetchall()

        state_lookup = {

            normalize_name(row["state_name"]): row["id"]

            for row in db_states

        }

        print(
            "Database states found:",
            len(db_states)
        )


        # ---------------------------------------------
        # FETCH LGD API STATES
        # ---------------------------------------------

        print("\nFetching LGD state data...")

        api_states = fetch_api_data("states")

        print(
            "LGD API states received:",
            len(api_states)
        )


        # ---------------------------------------------
        # CREATE LGD STATE CODE LOOKUP
        # ---------------------------------------------

        lgd_state_names = {

            str(state["code"]): state["name"]

            for state in api_states

        }


        # ---------------------------------------------
        # FETCH ALL DISTRICTS
        # ---------------------------------------------

        print("\nFetching all Indian districts...")

        api_districts = fetch_api_data("districts")

        print(
            "LGD API districts received:",
            len(api_districts)
        )


        # ---------------------------------------------
        # MATCH STATES AND PREPARE RECORDS
        # ---------------------------------------------

        records = []

        unmatched_states = set()

        for district in api_districts:

            lgd_state_code = str(
                district["state_code"]
            )

            api_state_name = lgd_state_names.get(
                lgd_state_code
            )

            if not api_state_name:

                unmatched_states.add(
                    f"Unknown LGD state code: {lgd_state_code}"
                )

                continue


            normalized_name = normalize_name(
                api_state_name
            )

            state_id = state_lookup.get(
                normalized_name
            )

            if state_id is None:

                unmatched_states.add(
                    api_state_name
                )

                continue


            records.append((

                state_id,

                district["name"],

                str(district["code"])

            ))


        # ---------------------------------------------
        # VALIDATE STATE MATCHING
        # ---------------------------------------------

        if unmatched_states:

            print("\nUnmatched states found:")

            for state in sorted(unmatched_states):

                print("-", state)

            raise Exception(
                "State matching incomplete. "
                "No districts were inserted."
            )


        if not records:

            raise Exception(
                "No district records received from API."
            )


        print(
            "\nAll district records matched successfully!"
        )


        # ---------------------------------------------
        # INSERT DISTRICTS INTO MYSQL
        # ---------------------------------------------

        print("\nInserting districts into database...")

        insert_query = """

            INSERT INTO districts
                (state_id, district_name, lgd_code)

            VALUES (%s, %s, %s)

            ON DUPLICATE KEY UPDATE

                district_name = VALUES(district_name)

        """

        cursor.executemany(
            insert_query,
            records
        )

        connection.commit()


        # ---------------------------------------------
        # DISPLAY IMPORT SUMMARY
        # ---------------------------------------------

        print("\n===================================")

        print("DISTRICT IMPORT COMPLETED!")

        print("===================================")

        print(
            "API districts received:",
            len(api_districts)
        )

        print(
            "District records processed:",
            len(records)
        )


        # ---------------------------------------------
        # VERIFY TOTAL DISTRICTS
        # ---------------------------------------------

        cursor.execute("""

            SELECT COUNT(*) AS total

            FROM districts

        """)

        result = cursor.fetchone()

        print(
            "\nTotal districts in database:",
            result["total"]
        )


        # ---------------------------------------------
        # STATE-WISE DISTRICT COUNT
        # ---------------------------------------------

        cursor.execute("""

            SELECT

                s.state_name,

                COUNT(d.id) AS total_districts

            FROM states s

            LEFT JOIN districts d

                ON s.id = d.state_id

            GROUP BY

                s.id,

                s.state_name

            ORDER BY

                s.state_name

        """)

        state_results = cursor.fetchall()

        print("\nSTATE-WISE DISTRICT COUNT")

        print("-----------------------------------")

        for row in state_results:

            print(

                f'{row["state_name"]}: '

                f'{row["total_districts"]}'

            )

        print("-----------------------------------")

        print("\nAll operations completed successfully!")


    # =================================================
    # ERROR HANDLING
    # =================================================

    except Exception as error:

        if connection and connection.is_connected():

            connection.rollback()

        print("\nIMPORT ERROR:")

        print(error)


    # =================================================
    # CLOSE MYSQL CONNECTION
    # =================================================

    finally:

        if cursor:

            cursor.close()

        if connection and connection.is_connected():

            connection.close()

            print("\nMySQL connection closed.")


# =====================================================
# 6. PROGRAM ENTRY POINT
# =====================================================

if __name__ == "__main__":

    main()
