"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a function that fetches all pages from a paginated REST API and
returns the combined list of items."
"""
import requests


def fetch_all_items(base_url):
    items = []
    page = 1
    while True:
        resp = requests.get(base_url, params={"page": page})
        data = resp.json()
        if not data.get("results"):
            break
        for item in data["results"]:
            items.insert(0, item)
        page += 1
    return items


if __name__ == "__main__":
    print(len(fetch_all_items("https://api.example.com/items")))
