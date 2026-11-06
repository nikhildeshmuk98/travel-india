
import requests

urls = [
    "https://overpass.kumi.systems/api/interpreter",
    "https://overpass.private.coffee/api/interpreter",
    "https://overpass-api.de/api/interpreter"
]

query = """
[out:json][timeout:25];

(
  nwr(around:10000,13.6316368,79.4231711)["tourism"];
  nwr(around:10000,13.6316368,79.4231711)["historic"];
  nwr(around:10000,13.6316368,79.4231711)["amenity"="place_of_worship"];
);

out center tags;
"""

headers = {
    "User-Agent": "TravelIndiaTourismApp/1.0"
}

for url in urls:

    print("\n" + "=" * 60)
    print("Testing:", url)

    try:

        response = requests.post(
            url,
            data={"data": query},
            headers=headers,
            timeout=(10, 45)
        )

        print("STATUS:", response.status_code)

        response.raise_for_status()

        data = response.json()

        elements = data.get("elements", [])

        print("TOTAL ELEMENTS:", len(elements))
        print("\nTOURIST PLACE NAMES:")

        for place in elements[:20]:

            name = place.get("tags", {}).get(
                "name",
                "Unnamed"
            )

            print("-", name)

        if elements:
            print("\nSUCCESS: This server returned places.")
            break

        print("\nServer responded, but no places found.")

    except requests.RequestException as error:

        print("SERVER FAILED:", error)

    except ValueError as error:

        print("INVALID RESPONSE:", error)

print("\nTEST COMPLETED.")
