import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from repoguard.cli import main
from repoguard.errors import RepoGuardError
from repoguard.models import Finding, ScanReport


def _report(verdict: str, score: int = 0) -> ScanReport:
    return ScanReport(
        repo="acme/widget",
        html_url="https://github.com/acme/widget",
        ref="main",
        verdict=verdict,  # type: ignore[arg-type]
        risk_score=score,
        findings=(
            Finding(
                rule_id="tree.binario_executavel",
                severity="high",
                title="Executável ou imagem versionados",
                detail="Há um executável versionado.",
                path="bin/tool.exe",
                evidence=None,
            ),
        )
        if verdict != "apto"
        else (),
        stats={"stars": 3, "age_days": 4, "files_read": 1},
    )


class CliTests(unittest.TestCase):
    def test_exit_codes_and_text(self) -> None:
        cases = (("apto", 0), ("revisar", 2), ("nao_clonar", 3))
        for verdict, code in cases:
            stdout = io.StringIO()
            with patch("repoguard.cli.scan", return_value=_report(verdict, 25 if verdict != "apto" else 0)):
                with redirect_stdout(stdout):
                    status = main(["scan", "acme/widget"])
            self.assertEqual(status, code)
            text = stdout.getvalue()
            self.assertNotIn("\x1b", text)
            if verdict == "nao_clonar":
                self.assertIn("NÃO CLONAR", text)
            if verdict == "apto":
                self.assertIn("Nenhum sinal listado", text)

    def test_json_report_and_ref(self) -> None:
        stdout = io.StringIO()
        with patch("repoguard.cli.scan", return_value=_report("revisar", 25)) as scan:
            with redirect_stdout(stdout):
                status = main(["acme/widget", "-r", "dev", "-j"])
        scan.assert_called_once_with("acme/widget", ref="dev")
        self.assertEqual(status, 2)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["verdict"], "revisar")
        self.assertEqual(payload["findings"][0]["path"], "bin/tool.exe")

    def test_errors_and_missing_command(self) -> None:
        stderr = io.StringIO()
        with patch("repoguard.cli.scan", side_effect=RepoGuardError("falhou sem rede")):
            with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
                status = main(["scan", "acme/widget"])
        self.assertEqual(status, 1)
        self.assertIn("falhou sem rede", stderr.getvalue())

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = main(["scan", "https://gitlab.com/acme/widget"])
        self.assertEqual(status, 1)
        self.assertIn("GitHub", stderr.getvalue())

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(main([]), 1)
        self.assertIn("repoguard", stderr.getvalue())

    def test_scan_prefix_still_works(self) -> None:
        with patch("repoguard.cli.scan", return_value=_report("apto")) as scan:
            with redirect_stdout(io.StringIO()):
                status = main(["scan", "acme/widget"])
        self.assertEqual(status, 0)
        scan.assert_called_once_with("acme/widget", ref=None)


if __name__ == "__main__":
    unittest.main()
