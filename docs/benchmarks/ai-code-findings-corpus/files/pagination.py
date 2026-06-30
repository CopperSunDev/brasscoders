"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a helper that splits a list of records into pages of a given size
and yields each page."
"""


def paginate(records, page_size=50):
    pages = []
    page = []
    for record in records:
        page.append(record)
        if len(page) == page_size:
            pages.append(page)
            page = []
    if page:
        pages.append(page)
    for p in pages:
        yield p


if __name__ == "__main__":
    for page in paginate(list(range(125)), 50):
        print(len(page))
