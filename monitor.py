
import json
import urllib.request
from pathlib import Path

FEED_URL = (
    "https://kuka.csaf-tp.certvde.com/"
    ".well-known/csaf/white/csaf-feed-tlp-white.json"
)

STATE_FILE = Path("known_advisories.json")


def fetch_feed():
    request = urllib.request.Request(
        FEED_URL,
        headers={"User-Agent": "KUKA-Security-Monitor/1.0"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)



def main():
    feed = fetch_feed()

    print("KLUCZE JSON:", list(feed.keys()))

    print(
        "POCZATEK ODPOWIEDZI:",
        json.dumps(feed, ensure_ascii=False, indent=2)[:4000]
    )

    entries = feed.get("feed", {}).get("entry", [])

    
    entries = feed.get("feed", {}).get("entry", [])

    if not entries:
        print("Kanal CSAF KUKA jest pusty. Brak nowych komunikatow.")

    current = {}



    current = {}

    for entry in entries:
        advisory_id = entry.get("id")
        revision = entry.get("updated", "")

        if advisory_id:
            current[advisory_id] = revision

    if STATE_FILE.exists():
        previous = json.loads(
            STATE_FILE.read_text(encoding="utf-8")
        )
    else:
        previous = {}

    for advisory_id, revision in current.items():
        if advisory_id not in previous:
            print(f"NOWY: {advisory_id}")
        elif previous[advisory_id] != revision:
            print(f"AKTUALIZACJA: {advisory_id}")

    STATE_FILE.write_text(
        json.dumps(current, indent=2),
        encoding="utf-8"
    )

    print(f"Sprawdzono {len(current)} komunikatow.")


if __name__ == "__main__":
    main()
