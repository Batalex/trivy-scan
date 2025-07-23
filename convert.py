"""Conversion script."""

import argparse
import json

import polars as pl

parser = argparse.ArgumentParser()
parser.add_argument("filename")
args = parser.parse_args()

with open(args.filename, "r") as fid:
    report = json.load(fid)

df = pl.DataFrame(report["Results"][0]["Vulnerabilities"]).filter(
    pl.col("Severity").is_in(["HIGH", "CRITICAL", "MEDIUM"])
)

df.write_excel("report.xlsx")
