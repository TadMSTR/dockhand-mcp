"""
Secret redaction for everything dockhand-mcp returns.

Two jobs live here, and they share one value-shape test on purpose:

* ``redact_container_env`` — inspect_container's Config.Env/Labels pass.
* ``mask_env_dump`` — Dockhand's own log, which carries whole ``.env`` files
  (dockhand-2026-10 p1 audit F-02). Applied to container logs, deploy logs and
  schedule-execution logs.

Never reduce either to a key-name list. The value-shape half is what catches a
credential under a key nobody predicted.
"""

from __future__ import annotations

import re
from typing import Any

# SECURITY: this is the ONLY thing standing between inspect_container's caller and
# every secret on the host. It was designed as a second layer behind Dockhand's own
# masking; measurement on 2026-09-07 showed that masking does not fire here at all.
#
# GET /api/containers/{id} is documented as masking a compose project's secret
# variables to KEY=***, and GET /api/containers/{id}/inspect is documented as not
# masking anything. Against forge's live Dockhand v1.0.46, both returned 322 of 322
# secret-shaped env vars UNMASKED across 123 containers — the string "***" appeared
# nowhere in either response. Dockhand masks variables it knows as a project's
# secrets, and forge's stacks supply env from env_file paths Dockhand's container
# cannot read (vikunja#542/#410). So the masking is real code that never fires here.
#
# Consequence: do not weaken this pass on the grounds that Dockhand also masks.
# It does not.
_SECRET_KEY = re.compile(
    # "PASS" is deliberately a bare substring, not \bPASS\b: the live miss that
    # prompted this was DFLY_requirepass, where "pass" has no word boundary.
    # It subsumes PASSWORD/PASSWD/PASSPHRASE. Likewise PWD for POSTGRES_PWD.
    # Over-matching here is cheap because a provably-benign value escapes below,
    # so AUTH does not redact the ~30 GF_AUTH_*=true config flags on this host.
    r"PASS|PWD|TOKEN|SECRET|CREDENTIAL|CREDS|APIKEY|API_KEY|ACCESS_KEY"
    r"|PRIVATE_KEY|_KEY|KEY_|KEYS|SALT|BEARER|DSN|AUTH|SIGNATURE|SIGNING",
    re.IGNORECASE,
)

# Values that cannot be a credential whatever their key is called. This is what
# makes the deliberately greedy key pattern above survivable.
_BENIGN_VALUE = re.compile(
    r"^(?:true|false|yes|no|on|off|none|null|nil|debug|info|warn|warning|error"
    r"|fatal|trace|silent|verbose|production|development|staging|test|always"
    r"|never|auto|enabled|disabled)$",
    re.IGNORECASE,
)
_NUMERIC_VALUE = re.compile(r"^-?\d+(?:\.\d+)?$")
_BARE_INTERPOLATION = re.compile(r"^\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)$")

# A single opaque token of any real length — the shape every secret on this host
# actually has. This is the half that catches a credential under a key nobody
# thought to pattern-match, which is the failure mode a key allowlist cannot fix:
# it can only ever be current up to the last audit that tried to defeat it.
_OPAQUE_CREDENTIAL = re.compile(r"^[A-Za-z0-9+/=_.~-]{20,}$")

# Credentials embedded in a URL value (postgres://user:pass@host) are invisible to
# a key-name test — the key is usually a bland *_URL. Many live here.
_URL_CREDENTIALS = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s/@]+@")

# A credential in a URL query string has no userinfo to strip and usually sits
# under a bland key like FEED_URL, so neither the key test nor the userinfo test
# sees it.
_URL_QUERY_SECRET = re.compile(
    r"(?P<sep>[?&])"
    r"(?P<name>[^=&\s]*(?:PASS|PWD|TOKEN|SECRET|KEY|AUTH|SIG|CREDENTIAL)[^=&\s]*)"
    r"=(?P<value>[^&\s]*)",
    re.IGNORECASE,
)

_REDACTED = "***REDACTED***"


def _is_benign_value(value: str) -> bool:
    """True when a value cannot be a credential regardless of its key's name.

    Only consulted for keys that do NOT look secret-shaped — see _redact_value,
    where a secret-shaped key gets a much narrower escape.
    """
    if _is_structurally_harmless(value):
        return True
    # An "@" means possible userinfo; whitespace means prose, not a token.
    if "@" in value or re.search(r"\s", value):
        return False
    if value.startswith("/"):
        return True  # absolute filesystem path
    if "://" in value:
        # A URL with no userinfo — benign unless it carries a secret-shaped
        # query parameter, e.g. ...?access_token=...
        return not _SECRET_KEY.search(value.partition("?")[2])
    return False


def _is_structurally_harmless(value: str) -> bool:
    """A value that cannot encode a credential at all: empty, a flag, a number, or
    a bare ``${NAME}`` reference. A reference with a default (``${X:-...}``) is
    not harmless, because the default can be the secret."""
    return bool(
        value == ""
        or _BENIGN_VALUE.match(value)
        or _NUMERIC_VALUE.match(value)
        or _BARE_INTERPOLATION.match(value)
    )


def redact_value(key: str, value: str) -> str:
    """Redact one key/value pair, defaulting to deny for anything unrecognised."""
    if _SECRET_KEY.search(key):
        # A secret-shaped key gets only the narrow escape. Deliberately NOT the
        # path/URL escape: a webhook URL stored under WEBHOOK_SECRET *is* the
        # secret, and letting the URL branch run first leaked exactly that.
        return value if _is_structurally_harmless(value) else _REDACTED

    if _is_benign_value(value):
        return value

    # The half a key allowlist cannot provide: an opaque token under a key
    # nobody thought to pattern-match.
    if _OPAQUE_CREDENTIAL.match(value):
        return _REDACTED

    # Otherwise the value is not itself a secret, but may still carry one.
    value = _URL_CREDENTIALS.sub(rf"\g<scheme>{_REDACTED}@", value)
    return _URL_QUERY_SECRET.sub(rf"\g<sep>\g<name>={_REDACTED}", value)


def _redact_env_entry(entry: str) -> str:
    """Redact one ``KEY=value`` string from a Docker ``Config.Env`` array."""
    if not isinstance(entry, str):
        return entry
    key, sep, value = entry.partition("=")
    if not sep:
        return entry
    return f"{key}{sep}{redact_value(key, value)}"


def redact_container_env(payload: Any) -> Any:
    """Return ``payload`` with secret-shaped values in Config.Env/Labels redacted.

    Scope, stated plainly because a redaction pass that overstates its reach is
    worse than none: this covers ``Config.Env`` and ``Config.Labels``. It does
    **not** inspect ``Config.Cmd``, ``Entrypoint`` or ``Args``, so a container
    started with a credential on its command line is still returned in the clear.
    inspect_container's docstring says so, and its output is to be treated as
    sensitive regardless.
    """
    if not isinstance(payload, dict):
        return payload
    out = dict(payload)
    config = out.get("Config")
    if isinstance(config, dict):
        config = dict(config)
        env = config.get("Env")
        if isinstance(env, list):
            config["Env"] = [_redact_env_entry(e) for e in env]
        labels = config.get("Labels")
        if isinstance(labels, dict):
            config["Labels"] = {
                k: (redact_value(str(k), v) if isinstance(v, str) else v) for k, v in labels.items()
            }
        out["Config"] = config
    return out


# ---------------------------------------------------------------------------
# Env-file dumps in text (dockhand-2026-10 p1 audit F-02)
# ---------------------------------------------------------------------------

# Dockhand 1.0.55's parseEnvFileContent() console.logs the whole .env, raw, on
# every compose-running stack action, and its UI and scheduler do the same. The
# frame, measured on a canary 2026-10-25 (a Docker timestamp leads each line
# when it comes back through /api/containers/{id}/logs):
#
#   ... INFO  [Git] PARSE ENV FILE CONTENT
#   ... INFO  [Git] ----------------------------------------
#   ... INFO  [Git] Raw content length: 134 chars
#   ... INFO  [Git] Raw content:
#   ... INFO  KEY=value            <- first file line carries the log prefix
#   # KEY=value                    <- the rest are bare
#   MULTI="first
#   continuation                   <- a multi-line value: no key on this line
#   last"
#   ... INFO  [Git] Total lines: 6
#
# The block mask is the layer that matters: it removes everything between
# "Raw content:" and "Total lines:", which is the only way to catch a quoted
# value's continuation lines. The Alloy drop (host-forge/configs#25) is
# line-shaped and cannot.

ENV_DUMP_PLACEHOLDER = "[env file content masked by dockhand-mcp]"

_DUMP_HEADER = re.compile(r"PARSE ENV FILE CONTENT")
_DUMP_START = re.compile(r"\bRaw content:\s*$")
_DUMP_END = re.compile(r"\[Git\] Total lines: (?P<n>\d+)\s*$")
# After the block, parseEnvFileContent prints a one-line summary of the lines it
# skipped, *with their content*: "Skipped lines (3): Line 2: # KEY=value...;
# Line 5 (no =): <continuation>". That is a commented-out line (cut at some
# length) and every continuation line of a multi-line value, in clear, outside
# the block. Found by this build's canary, 2026-10-25; the Alloy drop misses it.
_SKIPPED_LINES = re.compile(r"(?P<head>\[Git\] Skipped lines \(\d+\):).*$")
_SKIPPED_PLACEHOLDER = "[skipped env lines masked by dockhand-mcp]"

# Frame lines allowed between the header and "Raw content:". Anything else there
# means the format changed upstream, and the block starts early (fail closed).
_DUMP_FRAME = re.compile(r"\[Git\] (?:-{8,}|Raw content length: \d+ chars)\s*$")

# The env-line shape from host-forge/configs#25: an optional Docker timestamp,
# an optional "<ts> LEVEL  " Dockhand prefix, then KEY=, "# KEY=" or
# "export KEY=", where a key may carry dots and dashes. "- KEY=value" compose
# list items are handled by redact_compose, not here.
_ENV_LINE = re.compile(
    r"^(?P<prefix>(?:\S+Z\s+)?(?:\S+Z\s+[A-Z]+\s+)?\s*(?:#\s*)?(?:export\s+)?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)(?P<eq>\s*=)(?P<value>.*)$"
)


def _unquote(value: str) -> tuple[str, str]:
    """Split a surrounding quote pair off ``value``: ``('"', 'inner')``."""
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return value[0], value[1:-1]
    return "", value


def _opens_multiline(value: str) -> str:
    """The quote character if ``value`` opens a quoted value it does not close."""
    v = value.strip()
    if v[:1] in ("'", '"') and not (len(v) >= 2 and v.endswith(v[0])):
        return v[0]
    return ""


def _mask_env_line(line: str) -> tuple[str, str]:
    """Value-redact one env-shaped line. Returns (line, open_quote)."""
    m = _ENV_LINE.match(line)
    if not m:
        return line, ""
    key, raw = m.group("key"), m.group("value")
    quote = _opens_multiline(raw)
    if quote:
        # The rest of this value is on following lines with no key to test.
        return f"{m.group('prefix')}{key}{m.group('eq')}{_REDACTED}", quote
    q, inner = _unquote(raw.strip())
    redacted = redact_value(key, inner)
    if redacted == inner:
        return line, ""
    return f"{m.group('prefix')}{key}{m.group('eq')}{q}{redacted}{q}", ""


def mask_env_dump(text: str) -> tuple[str, int]:
    """Mask Dockhand env-file dumps, and env-shaped lines, in log text.

    Returns ``(masked_text, lines_masked)``. Fails closed both ways a ``tail``
    can cut a block: with the end marker missing, the block is masked to the end
    of the text; with the start missing, the N lines before ``Total lines: N``
    are masked. A quoted multi-line value that never closes is masked to the end.
    """
    if not isinstance(text, str) or not text:
        return text, 0
    out: list[str] = []
    masked = 0
    state = "normal"  # normal | header | block | quoted
    open_quote = ""
    floor = 0  # out[:floor] is already settled; an orphan end never reaches past it
    for line in text.split("\n"):
        end = _DUMP_END.search(line)
        if end and state in ("normal", "quoted"):
            # An end marker with no start: the head of the block was cut off,
            # e.g. by Dockhand's own ``tail``. The N lines before it are file
            # content, including any continuation line no other test can see.
            n = int(end.group("n"))
            cut = max(floor, len(out) - n)
            masked += len(out) - cut
            del out[cut:]
            out.append(ENV_DUMP_PLACEHOLDER)
            out.append(line)
            floor = len(out)
            state = "normal"
            continue
        if state == "block":
            if end:
                out.append(line)
                floor = len(out)
                state = "normal"
            else:
                masked += 1
            continue
        if state == "quoted":
            masked += 1
            if open_quote in line:
                state = "normal"
            continue
        if _DUMP_START.search(line):
            out.append(line)
            out.append(ENV_DUMP_PLACEHOLDER)
            state = "block"
            continue
        if state == "header":
            if _DUMP_FRAME.search(line):
                out.append(line)
                continue
            # Upstream changed the frame: treat this line as content.
            out.append(ENV_DUMP_PLACEHOLDER)
            masked += 1
            state = "block"
            continue
        if _DUMP_HEADER.search(line):
            out.append(line)
            state = "header"
            continue
        skipped = _SKIPPED_LINES.search(line)
        if skipped:
            out.append(f"{line[: skipped.start()]}{skipped.group('head')} {_SKIPPED_PLACEHOLDER}")
            masked += 1
            continue
        new, open_quote = _mask_env_line(line)
        if new != line:
            masked += 1
        out.append(new)
        if open_quote:
            state = "quoted"
    return "\n".join(out), masked


# A compose list item ("- KEY=value", optionally quoted) or a mapping entry
# ("KEY: value"). The value-shape test decides; image refs, paths and plain
# URLs pass through unchanged.
_COMPOSE_LIST_ITEM = re.compile(
    r"^(?P<prefix>\s*-\s+)(?P<q>[\"']?)(?P<key>[^=\s\"']+)=(?P<value>.*?)(?P=q)\s*$"
)
_COMPOSE_MAPPING = re.compile(
    r"^(?P<prefix>\s*)(?P<key>[A-Za-z0-9_.\-]+):(?P<sp>\s+)(?P<value>\S.*?)\s*$"
)


def redact_compose(text: str) -> tuple[str, int]:
    """Value-shape redaction over compose YAML text. Returns (text, values_redacted).

    Line-based by design: it does not parse YAML, so it cannot be confused by
    anchors or merge keys, and a value it cannot classify is redacted.
    """
    if not isinstance(text, str) or not text:
        return text, 0
    out: list[str] = []
    count = 0
    for line in text.split("\n"):
        m = _COMPOSE_LIST_ITEM.match(line)
        if m:
            value = m.group("value")
            redacted = redact_value(m.group("key"), value)
            if redacted != value:
                count += 1
                q = m.group("q")
                line = f"{m.group('prefix')}{q}{m.group('key')}={redacted}{q}"
            out.append(line)
            continue
        m = _COMPOSE_MAPPING.match(line)
        if m:
            q, inner = _unquote(m.group("value"))
            redacted = redact_value(m.group("key"), inner)
            if redacted != inner:
                count += 1
                line = f"{m.group('prefix')}{m.group('key')}:{m.group('sp')}{q}{redacted}{q}"
        out.append(line)
    return "\n".join(out), count
