"""Tests that every advisory pip-audit ignores in CI is documented as an accepted risk (T1.6)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY = ROOT / "docs" / "SECURITY.md"
# pip-audit's argparse takes both "--ignore-vuln ID" and "--ignore-vuln=ID".
IGNORE_FLAG = re.compile(r"--ignore-vuln(?:\s+|=)(\S+)")


def ignored_ids(workflow: str) -> list[str]:
    """Return the advisory IDs passed to pip-audit with --ignore-vuln in a workflow's text."""
    return IGNORE_FLAG.findall(workflow)


def accepted_risk_rows(doc: str) -> list[str]:
    """Return the table rows of the "Accepted risks" section of a SECURITY.md text."""
    section = doc.split("## Accepted risks", 1)[1].split("\n## ", 1)[0]
    return [line for line in section.splitlines() if line.startswith("| ")]


def is_documented(advisory: str, rows: list[str]) -> bool:
    """Return whether the whole advisory ID appears in one of the rows (not part of a longer ID)."""
    # "PYSEC-2026-31" must not match a row for "PYSEC-2026-311" (code review on PR #58).
    whole_id = re.compile(rf"(?<![\w-]){re.escape(advisory)}(?![\w-])")
    return any(whole_id.search(row) for row in rows)


def _ci_ids() -> list[str]:
    """Return the advisory IDs the real CI workflow ignores."""
    return ignored_ids(CI.read_text(encoding="utf-8"))


def test_ci_ignores_some_advisories():
    """The audit step passes its ignores as --ignore-vuln flags, so the check below has input."""
    assert _ci_ids()


def test_every_ignored_advisory_has_an_accepted_risk_row():
    """No advisory is ignored in CI without its row under "Accepted risks" (security rules)."""
    rows = accepted_risk_rows(SECURITY.read_text(encoding="utf-8"))
    missing = [advisory for advisory in _ci_ids() if not is_documented(advisory, rows)]
    assert missing == [], f"ignored in CI without an accepted-risk row: {missing}"


def test_no_advisory_is_ignored_twice():
    """Each advisory is ignored once."""
    ids = _ci_ids()
    assert len(ids) == len(set(ids))


# --- The helpers on small samples (T1.7) ----------------------------------------------------------

SAMPLE_DOC = """# Security

## Accepted risks

| Advisory | Package | Why it does not apply | Review |
|---|---|---|---|
| PYSEC-2026-311 / CVE-2026-45829 (GHSA-f4j7-r4q5-qw2c) | chromadb | no server | fixed release |
| CVE-2026-112395 (GHSA-462x-pgg6-55fp) | pillow | no image | streamlit allows 13 |

## Known limits

| CVE-2026-999999 | not an accepted risk |
"""


def test_both_flag_forms_are_read():
    """A space or an equals sign after --ignore-vuln both give the ID."""
    workflow = "pip-audit . --ignore-vuln PYSEC-2026-311 --ignore-vuln=GHSA-462x-pgg6-55fp\n"
    assert ignored_ids(workflow) == ["PYSEC-2026-311", "GHSA-462x-pgg6-55fp"]


def test_only_the_accepted_risks_rows_are_read():
    """The rows come from the "Accepted risks" table only: its header and two rows."""
    rows = accepted_risk_rows(SAMPLE_DOC)
    assert len(rows) == 3
    assert not is_documented("CVE-2026-999999", rows)


def test_a_whole_id_in_a_row_is_documented():
    """An ID, its alias or its GHSA in a row counts as documented."""
    rows = accepted_risk_rows(SAMPLE_DOC)
    for advisory in ("PYSEC-2026-311", "CVE-2026-45829", "GHSA-f4j7-r4q5-qw2c", "CVE-2026-112395"):
        assert is_documented(advisory, rows), advisory


def test_a_truncated_or_longer_id_is_not_documented():
    """Part of a documented ID, or a documented ID with more after it, is not documented."""
    rows = accepted_risk_rows(SAMPLE_DOC)
    for advisory in ("PYSEC-2026-31", "CVE-2026-11239", "PYSEC-2026-3110", "CVE-2026-1123950"):
        assert not is_documented(advisory, rows), advisory
