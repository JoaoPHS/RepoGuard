"""Texto do relatório para o terminal. Não usa cor vinda do repositório."""

from __future__ import annotations

from repoguard.models import ScanReport
from repoguard.timeutil import days_phrase

_VERDICT = {
    "apto": "APTO",
    "revisar": "REVISAR",
    "nao_clonar": "NÃO CLONAR",
}
_SEVERITY = {
    "critical": "crítico",
    "high": "alto",
    "medium": "médio",
    "low": "baixo",
    "info": "info",
}


def render_report(report: ScanReport) -> str:
    age = report.stats.get("age_days")
    age_text = days_phrase(age) if isinstance(age, int) else "desconhecida"
    lines = [
        f"RepoGuard — {report.repo}",
        f"Veredito: {_VERDICT[report.verdict]}",
        f"Risco: {report.risk_score}/100",
        f"Ref: {report.ref}",
        (
            f"Estrelas: {report.stats.get('stars', 0)} | Idade: {age_text} | "
            f"Arquivos lidos: {report.stats.get('files_read', 0)}"
        ),
        "",
    ]
    if not report.findings:
        lines.append("Nenhum sinal listado pelas regras desta versão.")
    else:
        lines.append(f"Achados ({len(report.findings)})")
        for finding in report.findings:
            header = f"[{_SEVERITY[finding.severity]}] {finding.rule_id}"
            if finding.path:
                header += f"  {finding.path}"
            lines.append(header)
            lines.append(f"  {finding.title}")
            lines.append(f"  {finding.detail}")
            if finding.evidence:
                lines.append(f"  Trecho: {finding.evidence}")
    lines.append("")
    return "\n".join(lines)
