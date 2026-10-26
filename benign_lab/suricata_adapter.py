"""Suricata eve.json -> LAB_AUDIT-shaped detection records, for feeding
response_metrics.compute() the SAME way this codebase already feeds it
this project's own controller's log-derived records -- see that
module's own docstring for what `records`/`kind='detection'` means.

Why this exists: evaluating Suricata (an off-the-shelf IDS baseline) on
the exact same tD/TD metrics as this project's own controller, without
modifying response_metrics.py at all -- it only ever reads `records`,
never cares where they came from. One Suricata alert line becomes one
detection record; `_first()` in response_metrics.py already picks the
earliest one matching an attacker IP, so no de-duplication/aggregation
is done here deliberately -- that selection logic already exists
upstream and duplicating it here would be two sources of truth for the
same decision.

Confirmed on a real run (isp-ddos-ryu's own vm-lab, `nids` VM mirroring
`pe`'s br-ent over a GRE tunnel -- see that repo's
deploy/vm-lab/ansible/roles/nids_suricata/ for how the IDS itself is
provisioned): a live hping3 SYN flood produced real alert lines with
exactly the fields this module reads, using a local threshold rule
(ET Open alone does not fire on a raw-rate flood -- see that role's own
local.rules for why).
"""
import json
from datetime import datetime, timezone

# Suricata's own ISO8601 variant: "YYYY-MM-DDTHH:MM:SS.ffffff+HHMM" --
# microseconds always present, UTC offset WITHOUT a colon (confirmed on
# a real eve.json -- "2026-10-25T05:59:19.553753+0000"). datetime.
# fromisoformat() cannot parse this on Python < 3.11 (it requires
# "+HH:MM"), so this uses strptime with %z, which has accepted the
# no-colon offset form since Python 3.7 -- no extra dependency needed.
_EVE_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


def _parse_timestamp(raw):
    """Suricata's `timestamp` field -> epoch seconds (float, UTC). None
    if the field is missing or doesn't match the expected format --
    callers should treat that line as unusable, not crash on it (this
    reads live operational logs, not a trusted/controlled format)."""
    if not raw:
        return None
    try:
        dt = datetime.strptime(raw, _EVE_TS_FORMAT)
    except ValueError:
        return None
    return dt.astimezone(timezone.utc).timestamp()


def parse_eve_json(path, domain=None):
    """Read one eve.json file (JSON Lines -- one object per line, same
    format Suricata's own `eve-log` output writes) and yield a
    LAB_AUDIT-shaped `kind='detection'` dict per `event_type="alert"`
    line. Skips every other event_type (flow/stats/etc. -- this role's
    own suricata.yaml.j2 already restricts `types:` to `alert` for
    exactly this reason, but a stale/hand-edited config could still emit
    others) and skips lines that fail to parse as JSON or as Suricata's
    timestamp format, rather than raising -- an eve.json is a live
    operational log, a malformed line from a fast-rotating file read
    mid-write is expected, not exceptional.

    `domain` is optional and purely informational (response_metrics.py's
    own tD/TD matching only ever uses the IP, never this field) -- pass
    it if the caller already knows which domain's mirror feeds this
    particular Suricata instance (this project's own vm-lab mirrors
    ALL domains through the one `pe` bridge, so there is no single
    answer for it there; leave it unset in that case)."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("event_type") != "alert":
                continue
            ts = _parse_timestamp(event.get("timestamp"))
            src_ip = event.get("src_ip")
            if ts is None or not src_ip:
                continue
            alert = event.get("alert") or {}
            detection = {
                "src_ip": src_ip,
                "signature": alert.get("signature"),
                "signature_id": alert.get("signature_id"),
                # 0, not None/omitted -- response_metrics.py's own tD0
                # computation (`tD - activation_delay_s`) requires a
                # finite number; Suricata has no activation-hysteresis
                # concept (unlike this project's own controller's
                # ENTERPRISE_ACTIVATION_* etc.), so tD0 == tD here,
                # exactly like a controller detection the project's own
                # DetectionResult.activation_delay_s docstring already
                # documents as exempt from that hysteresis.
                "activation_delay_s": 0,
            }
            if domain:
                detection["domain"] = domain
            yield {
                "timestamp": ts,
                "kind": "detection",
                "detection": detection,
                # Kept for traceability back to the raw alert -- never
                # read by response_metrics.py itself, purely for a human
                # (or a future adapter) auditing why a given record
                # exists.
                "source": "suricata",
                "dest_ip": event.get("dest_ip"),
                "proto": event.get("proto"),
            }


def load_eve_json(path, domain=None):
    """Same as parse_eve_json(), materialized as a list -- what
    response_metrics.compute()'s own `records` parameter expects
    (it sorts internally, so order here doesn't matter)."""
    return list(parse_eve_json(path, domain=domain))
