"""Turn a gitleaks JSON report into GitHub check annotations.

Only the file, line, rule id and commit go into an annotation, never the
secret, the match or the line's text: annotations on a public repository are
public, and gitleaks' --redact covers its console output, not this.
"""

from __future__ import annotations

import json
import sys


def _clean(value: object) -> str:
    # Workflow-command metacharacters would end or split the annotation.
    return str(value).replace("%", "%25").replace("\r", "").replace("\n", "").replace(",", "%2C")


def main(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        findings = json.load(fh) or []
    for f in findings:
        commit = str(f.get("Commit") or "")[:12]
        where = f" in {commit}" if commit else ""
        print(
            f"::error file={_clean(f.get('File', ''))},line={int(f.get('StartLine') or 1)},"
            f"title=gitleaks::{_clean(f.get('RuleID', 'finding'))}{_clean(where)}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
