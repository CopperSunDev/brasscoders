"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a function that reads a CSV of sales rows (region,amount) and
returns a formatted text report of total sales per region."
"""
import csv


def build_sales_report(csv_path):
    totals = {}
    with open(csv_path, newline="") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        for row in reader:
            region, amount = row[0], float(row[1])
            totals[region] = totals.get(region, 0.0) + amount

    report = ""
    for region in sorted(totals):
        report += f"{region}: ${totals[region]:,.2f}\n"
    return report


if __name__ == "__main__":
    print(build_sales_report("sales.csv"))
