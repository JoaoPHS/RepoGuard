import unittest
from datetime import timedelta

from repoguard.models import Finding
from repoguard.scoring import (
    BLOCK_SCORE,
    REVIEW_SCORE,
    adjust,
    is_reputable,
    is_young_unknown,
    verdict_for,
)
from support import NOW, make_snapshot

from repoguard.models import RawFinding


def _raw(severity: str, **kwargs) -> RawFinding:
    return RawFinding(
        rule_id=kwargs.get("rule_id", "teste"),
        severity=severity,  # type: ignore[arg-type]
        title="Titulo",
        detail="Detalhe",
        dampable=kwargs.get("dampable", False),
        escalate_when_young=kwargs.get("escalate_when_young", False),
    )


def _finding(severity: str, index: int = 0) -> Finding:
    return Finding(rule_id=f"r{index}", severity=severity, title="t", detail="d")  # type: ignore[arg-type]


class ScoringTests(unittest.TestCase):
    def test_verdicts_follow_severity_and_score(self) -> None:
        score, verdict = verdict_for([_finding("low", i) for i in range(7)])
        self.assertEqual((score, verdict), (28, "apto"))

        score, verdict = verdict_for([_finding("low", i) for i in range(8)])
        self.assertEqual((score, verdict), (32, "revisar"))
        self.assertGreaterEqual(score, REVIEW_SCORE)

        score, verdict = verdict_for([_finding("high")])
        self.assertEqual((score, verdict), (25, "revisar"))

        score, verdict = verdict_for([_finding("critical")])
        self.assertEqual((score, verdict), (40, "nao_clonar"))
        self.assertLess(score, BLOCK_SCORE)

        score, verdict = verdict_for([_finding("high", i) for i in range(3)])
        self.assertEqual((score, verdict), (75, "nao_clonar"))

        score, verdict = verdict_for([_finding("critical", i) for i in range(5)])
        self.assertEqual(score, 100)
        self.assertEqual(verdict, "nao_clonar")

    def test_reputation_boundaries(self) -> None:
        young = make_snapshot(created_at=NOW - timedelta(days=29), stars=9)
        not_young_age = make_snapshot(created_at=NOW - timedelta(days=30), stars=0)
        not_young_stars = make_snapshot(created_at=NOW - timedelta(days=29), stars=10)
        reputable = make_snapshot(created_at=NOW - timedelta(days=180), stars=50)
        almost_old = make_snapshot(created_at=NOW - timedelta(days=179), stars=50)
        almost_starred = make_snapshot(created_at=NOW - timedelta(days=180), stars=49)
        self.assertTrue(is_young_unknown(young))
        self.assertFalse(is_young_unknown(not_young_age))
        self.assertFalse(is_young_unknown(not_young_stars))
        self.assertTrue(is_reputable(reputable))
        self.assertFalse(is_reputable(almost_old))
        self.assertFalse(is_reputable(almost_starred))

    def test_readme_signal_escalates_or_dampens(self) -> None:
        raw = _raw("medium", dampable=True, escalate_when_young=True, rule_id="readme.curl_pipe_shell")
        young = make_snapshot(created_at=NOW - timedelta(days=2), stars=0)
        middle = make_snapshot(created_at=NOW - timedelta(days=60), stars=0)
        popular = make_snapshot(created_at=NOW - timedelta(days=400), stars=200)
        self.assertEqual(adjust(raw, young).severity, "high")
        self.assertEqual(adjust(raw, middle).severity, "medium")
        self.assertEqual(adjust(raw, popular).severity, "low")

    def test_critical_is_not_dampened_by_reputation(self) -> None:
        raw = _raw("critical", dampable=False, rule_id="install.hook_rede")
        popular = make_snapshot(created_at=NOW - timedelta(days=400), stars=200)
        self.assertEqual(adjust(raw, popular).severity, "critical")

    def test_evidence_from_the_repository_cannot_color_the_terminal(self) -> None:
        raw = _raw("low", rule_id="teste")
        raw = RawFinding(
            rule_id="teste",
            severity="low",
            title="Titulo",
            detail="Detalhe",
            evidence="ok \x1b[31mvermelho\x1b[0m \u200b",
        )
        cleaned = adjust(raw, make_snapshot()).evidence or ""
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\u200b", cleaned)
        self.assertIn("vermelho", cleaned)


if __name__ == "__main__":
    unittest.main()
