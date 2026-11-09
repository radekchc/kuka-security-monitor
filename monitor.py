
import json
import os
import urllib.request
from pathlib import Path

FEED_URL = (
    "https://kuka.csaf-tp.certvde.com/"
    ".well-known/csaf/white/csaf-feed-tlp-white.json"
)

API = "https://api.github.com"
REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["GITHUB_TOKEN"]

ALERT_FILE = Path("kuka-alerts.txt")


def request_json(url, method="GET", data=None):
    headers = {
        "User-Agent": "KUKA-Security-Monitor",
        "Accept": "application/vnd.github+json"
    }

    if url.startswith(API + "/"):
        headers["Authorization"] = f"Bearer {TOKEN}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"

    payload = (
        json.dumps(data).encode("utf-8")
        if data is not None else None
    )

    if payload is not None:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url,
        data=payload,
        headers=headers,
        method=method
    )

    with urllib.request.urlopen(req, timeout=40) as response:
        return json.load(response)


def get_existing_issues():
    issues = {}
    page = 1

    while True:
        url = (
            f"{API}/repos/{REPO}/issues"
            f"?state=all&per_page=100&page={page}"
        )
        batch = request_json(url)

        for issue in batch:
            if "pull_request" in issue:
                continue

            body = issue.get("body") or ""

            for line in body.splitlines():
                if line.startswith("KUKA-CSAF-ID: "):
                    advisory_id = line.split(": ", 1)[1]
                    issues[advisory_id] = issue
                    break

        if len(batch) < 100:
            break

        page += 1

    return issues


def save_alert(event_type, advisory_id, updated, url):
    with ALERT_FILE.open("a", encoding="utf-8") as f:
        f.write(
            f"{event_type} | {advisory_id} | "
            f"{updated} | {url}\n"
        )


def main():
    feed = request_json(FEED_URL)

    entries = feed.get("feed", {}).get("entry")

    if not isinstance(entries, list):
        raise RuntimeError("Nieprawidlowa struktura CSAF.")

    print(f"Liczba komunikatow: {len(entries)}")

    if not entries:
        print("Kanal KUKA jest pusty. Brak komunikatow.")
        return

    existing = get_existing_issues()

    for entry in entries:
        advisory_id = entry.get("id")
        updated = entry.get("updated", "")
        title = entry.get("title", advisory_id)

        links = entry.get("link", [])
        advisory_url = next(
            (
                link.get("href")
                for link in links
                if link.get("rel") in ("alternate", "self")
            ),
            ""
        )

        if not advisory_id:
            raise RuntimeError("Wpis CSAF bez identyfikatora.")

        if not updated:
            raise RuntimeError(
                f"Brak daty aktualizacji: {advisory_id}"
            )

        body = (
            f"KUKA-CSAF-ID: {advisory_id}\n\n"
            f"**Komunikat:** {title}\n\n"
            f"**Ostatnia aktualizacja:** {updated}\n\n"
            f"**Link:** {advisory_url or FEED_URL}\n\n"
            "Sprawdz produkty i wersje w ERP."
        )

        if advisory_id not in existing:
            request_json(
                f"{API}/repos/{REPO}/issues",
                method="POST",
                data={
                    "title": f"[KUKA CSAF] {title}",
                    "body": body
                }
            )

            save_alert(
                "NOWY",
                advisory_id,
                updated,
                advisory_url or FEED_URL
            )

            print(f"NOWY: {advisory_id}")

        else:
            issue = existing[advisory_id]

            if issue.get("body") != body:
                request_json(
                    f"{API}/repos/{REPO}/issues/{issue['number']}",
                    method="PATCH",
                    data={
                        "title": f"[KUKA CSAF] {title}",
                        "body": body
                    }
                )

                save_alert(
                    "AKTUALIZACJA",
                    advisory_id,
                    updated,
                    advisory_url or FEED_URL
                )

                print(f"AKTUALIZACJA: {advisory_id}")

            else:
                print(f"BEZ ZMIAN: {advisory_id}")

    print("Monitoring KUKA zakonczony.")


if __name__ == "__main__":
    main()
