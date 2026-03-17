"""Command-line interface for iocextract.

Subcommands
-----------
* ``extract``  read files (or stdin), print classified IOCs as JSON or a table
* ``defang``   print a safe-to-share version of the given text / stdin
* ``refang``   undo defanging on the given text / stdin
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .defang import defang, refang
from .extract import extract
from .models import IOCType


def _read_inputs(paths: list[str]) -> str:
    if not paths:
        return sys.stdin.read()
    chunks: list[str] = []
    for path in paths:
        if path == "-":
            chunks.append(sys.stdin.read())
        else:
            with open(path, encoding="utf-8", errors="replace") as fh:
                chunks.append(fh.read())
    return "\n".join(chunks)


def _cmd_extract(args: argparse.Namespace) -> int:
    text = _read_inputs(args.files)
    result = extract(text)

    if args.type:
        wanted = {IOCType(t) for t in args.type}
        result.iocs = [ioc for ioc in result.iocs if ioc.type in wanted]

    if args.format == "json":
        print(result.to_json(indent=None if args.compact else 2))
    else:  # table
        if not result.iocs:
            print("no indicators found", file=sys.stderr)
        for ioc in result.iocs:
            value = ioc.defanged if args.defang else ioc.value
            print(f"{ioc.type.value:<7} {value}")
    return 0


def _cmd_defang(args: argparse.Namespace) -> int:
    text = args.text if args.text else sys.stdin.read()
    print(defang(text), end="" if text.endswith("\n") else "\n")
    return 0


def _cmd_refang(args: argparse.Namespace) -> int:
    text = args.text if args.text else sys.stdin.read()
    print(refang(text), end="" if text.endswith("\n") else "\n")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iocextract",
        description="Extract and defang Indicators of Compromise from text.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ext = sub.add_parser("extract", help="extract IOCs from files or stdin")
    p_ext.add_argument("files", nargs="*", help="input files ('-' for stdin)")
    p_ext.add_argument(
        "-f", "--format", choices=("json", "table"), default="json",
        help="output format (default: json)",
    )
    p_ext.add_argument(
        "-t", "--type", action="append", choices=[t.value for t in IOCType],
        help="restrict output to this IOC type (repeatable)",
    )
    p_ext.add_argument(
        "--defang", action="store_true",
        help="show defanged values in table output",
    )
    p_ext.add_argument(
        "--compact", action="store_true", help="single-line JSON output",
    )
    p_ext.set_defaults(func=_cmd_extract)

    p_def = sub.add_parser("defang", help="defang text for safe sharing")
    p_def.add_argument("text", nargs="?", help="text (default: read stdin)")
    p_def.set_defaults(func=_cmd_defang)

    p_ref = sub.add_parser("refang", help="undo defanging")
    p_ref.add_argument("text", nargs="?", help="text (default: read stdin)")
    p_ref.set_defaults(func=_cmd_refang)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
