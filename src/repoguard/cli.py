"""Comando repoguard. A URL vai direto: repoguard owner/repo."""

from __future__ import annotations

import argparse
import json
import sys

from repoguard.errors import RepoGuardError
from repoguard.models import Verdict
from repoguard.render import render_report
from repoguard.scanner import scan

_EXIT: dict[Verdict, int] = {
    "apto": 0,
    "revisar": 2,
    "nao_clonar": 3,
}


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = _parser()
    if argv is None:
        argv = sys.argv[1:]
    argv = _normalize(list(argv))
    if not argv:
        parser.print_help(sys.stderr)
        return 1
    args = parser.parse_args(argv)
    try:
        report = scan(args.url, ref=args.ref)
    except RepoGuardError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if args.json:
        json.dump(report.to_dict(), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_report(report))
    return _EXIT[report.verdict]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repoguard",
        description="Avalia um repositório do GitHub antes da clonagem, só pela API.",
    )
    parser.add_argument("url", help="owner/repo ou a URL do GitHub")
    parser.add_argument("-j", "--json", action="store_true", help="Relatório em JSON.")
    parser.add_argument("-r", "--ref", default=None, help="Branch, tag ou commit.")
    return parser


def _normalize(argv: list[str]) -> list[str]:
    if argv and argv[0] == "scan":
        return argv[1:]
    return argv


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue


if __name__ == "__main__":
    raise SystemExit(main())
