#!/usr/bin/env python3
"""
Extend fixtures/iocs.json with additional compromised-package names.

RippleGuard ships a small seed list so the evaluation harness works out of the
box. That list is deliberately incomplete, and we do not auto-scrape vendor
blogs: IOC lists must be reviewed by a human before they are used as ground
truth for a metric you intend to quote.

Usage:
    python scripts/fetch_iocs.py --add chalk debug ansi-styles
    python scripts/fetch_iocs.py --from-file my-ioc-list.txt
    python scripts/fetch_iocs.py --show

Where to source names (all public):
  * CISA alert, "Widespread Supply Chain Compromise Impacting npm Ecosystem"
    https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
  * Checkmarx Zero, Wiz, Unit 42, Datadog Security Labs and ReversingLabs
    write-ups on the Shai-Hulud waves, each of which publishes a package list.
  * Datadog's open malicious-software-packages dataset.

Record where each batch came from in the `source` field. A metric computed
against a list of unknown provenance is not evidence.
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
IOC = ROOT / "fixtures" / "iocs.json"


def load() -> dict:
    return json.loads(IOC.read_text())


def save(data: dict) -> None:
    IOC.write_text(json.dumps(data, indent=2) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--add", nargs="+", metavar="PKG", help="package names to add")
    ap.add_argument("--from-file", metavar="PATH",
                    help="newline-delimited file of package names")
    ap.add_argument("--source", default="",
                    help="note describing where this batch came from")
    ap.add_argument("--show", action="store_true", help="print the current list")
    args = ap.parse_args()

    data = load()
    if args.show:
        try:
            print(f"{len(data['packages'])} packages")
            print("source:", data.get("source", ""))
            for p in sorted(data["packages"]):
                print(" ", p)
        except BrokenPipeError:
            # Piping into `head` closes stdout early; that's a normal exit,
            # not an error, so swallow it instead of printing a traceback.
            sys.stderr.close()
        return 0

    new: list[str] = list(args.add or [])
    if args.from_file:
        new += [l.strip() for l in pathlib.Path(args.from_file).read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    if not new:
        ap.print_help()
        return 1

    before = set(data["packages"])
    data["packages"] = sorted(before | set(new))
    if args.source:
        data["source"] = (data.get("source", "") + " | " + args.source).strip(" |")
    save(data)
    print(f"added {len(set(new) - before)} new package(s); "
          f"{len(data['packages'])} total")
    print("Remember to record provenance with --source before quoting a metric.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
