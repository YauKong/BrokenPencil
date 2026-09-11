"""Read dispositions from completed, hash-bound resolution evidence only.

Original proposals stay immutable. Projection bytes are deliberately not inputs
here: they are derived from this canonical evidence, not its authentication.
"""

import hashlib
import json
import stat

from .errors import ValidationError
from .catalog import _parse_catalog_bytes
from .paths import validate_identifier
from .records import parse_record


_OUTCOMES = {
    "confirm-candidate": "accepted-record",
    "change-owner": "accepted-record",
    "sources-only": "source-retained",
    "knowledge-base-candidate": "knowledge-base-candidate",
    "keep-unresolved": "unresolved",
}
_KEYS = frozenset((
    "schema_version", "evidence_kind", "transaction_id", "proposal_id",
    "decision_state", "outcome", "proposal_sha256", "snapshot_sha256",
    "report_sha256", "decisions_sha256", "packet_sha256", "rewrite_sha256",
    "memory_id", "record_path", "record_revision", "body_sha256",
))


def load_resolution_outcomes(reader):
    """Return proposal-path -> outcome using the caller's bounded read adapter."""
    # Lazy import avoids the projection/transaction module initialization cycle.
    from .resolution_transactions import (
        _json_bytes, _load_resolution_journal, _reject_duplicate_keys, _valid_digest,
    )

    def decode(raw):
        try:
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, ValueError) as error:
            raise ValidationError("invalid resolution outcome input") from error
        if not isinstance(document, dict):
            raise ValidationError("invalid resolution outcome input")
        return document

    def bound_bytes(activation, staged=False):
        raw = reader.read(activation["stage_path"] if staged else activation["target"])
        if hashlib.sha256(raw).hexdigest() != activation["desired_sha256"]:
            raise ValidationError("resolution outcome activation digest changed")
        return raw

    current_raw = reader.read(".agent-memory/state/catalog.json")
    _parse_catalog_bytes(reader.root, current_raw)
    current_catalog = decode(current_raw)
    outcomes = {}
    transaction_root = ".agent-memory/transactions"
    for name in reader.inventory(transaction_root, "resolution"):
        directory = transaction_root + "/" + name
        metadata = (reader.root / directory).lstat()
        # inventory() validates reparse points before any directory is followed.
        if not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            continue
        names = reader.inventory(directory, "resolution")
        if "journal.json" not in names:
            continue
        preliminary = decode(reader.read(directory + "/journal.json"))
        if preliminary.get("operation") != "apply-proposal-resolution":
            continue
        _, _, journal = _load_resolution_journal(reader.root, name, reader.read)
        if journal["status"] != "completed":
            continue
        if current_catalog["revision"] < journal["predicted_catalog_revision"]:
            raise ValidationError("completed resolution catalog was not activated")
        activations = {item["target"]: item for item in journal["activations"]}
        staged_raw = bound_bytes(journal["activations"][-1], staged=True)
        _parse_catalog_bytes(reader.root, staged_raw)
        staged_catalog = decode(staged_raw)
        if staged_catalog["revision"] != journal["predicted_catalog_revision"]:
            raise ValidationError("resolution staged catalog revision mismatch")
        if current_catalog["revision"] == staged_catalog["revision"] and current_catalog != staged_catalog:
            raise ValidationError("resolution catalog endpoint mismatch")
        for relative in journal["evidence_paths"]:
            raw = bound_bytes(activations[relative])
            if bound_bytes(activations[relative], staged=True) != raw:
                raise ValidationError("resolution evidence stage mismatch")
            evidence = decode(raw)
            if (
                set(evidence) != _KEYS or raw != _json_bytes(evidence)
                or evidence["schema_version"] != 1
                or evidence["evidence_kind"] != "proposal-resolution-outcome"
                or evidence["transaction_id"] != name
                or evidence["packet_sha256"] != journal["packet_sha256"]
                or not isinstance(evidence["decision_state"], str)
                or _OUTCOMES.get(evidence["decision_state"]) != evidence["outcome"]
            ):
                raise ValidationError("invalid resolution outcome binding")
            proposal_id = evidence["proposal_id"]
            validate_identifier(proposal_id, "proposal_id")
            if relative != directory + "/resolution-evidence/" + proposal_id + ".json":
                raise ValidationError("resolution evidence path mismatch")
            for key in ("proposal_sha256", "snapshot_sha256", "report_sha256", "decisions_sha256", "packet_sha256"):
                if not _valid_digest(evidence[key]):
                    raise ValidationError("invalid resolution outcome digest")
            proposal_path = ".agent-memory/state/proposals/" + proposal_id + ".json"
            if hashlib.sha256(reader.read(proposal_path)).hexdigest() != evidence["proposal_sha256"]:
                raise ValidationError("resolved proposal digest changed")
            if evidence["outcome"] == "accepted-record":
                validate_identifier(evidence["memory_id"], "memory_id")
                record_path = evidence["record_path"]
                if (not isinstance(record_path, str)
                        or type(evidence["record_revision"]) is not int
                        or evidence["record_revision"] < 1
                        or not _valid_digest(evidence["body_sha256"])
                        or record_path not in journal["record_paths"]):
                    raise ValidationError("resolution record is not journaled")
                record_raw = bound_bytes(activations[record_path], staged=True)
                try:
                    envelope, _ = parse_record(record_raw.decode("utf-8"))
                except UnicodeDecodeError as error:
                    raise ValidationError("invalid resolution record") from error
                entry = staged_catalog["records"].get(evidence["memory_id"])
                current = current_catalog["records"].get(evidence["memory_id"])
                if (
                    not _valid_digest(evidence["rewrite_sha256"])
                    or envelope.memory_id != evidence["memory_id"]
                    or envelope.revision != evidence["record_revision"]
                    or envelope.body_sha256 != evidence["body_sha256"]
                    or not isinstance(entry, dict) or entry.get("relative_path") != record_path
                    or entry["revision"] != envelope.revision
                    or not current or current["revision"] < envelope.revision
                    or any(current[key] != entry[key] for key in ("memory_id", "record_type", "owner_scope", "project"))
                ):
                    raise ValidationError("accepted resolution record binding mismatch")
            elif any(evidence[key] is not None for key in (
                "memory_id", "rewrite_sha256", "record_path", "record_revision", "body_sha256",
            )):
                raise ValidationError("no-record outcome contains a record")
            previous = outcomes.get(proposal_path)
            # A deferred decision is not a contrary terminal disposition. Keep
            # its immutable history without resurrecting a subsequently resolved
            # proposal. Conflicting non-deferred dispositions still fail closed.
            if (previous is not None and previous != evidence["outcome"]
                    and previous != "unresolved" and evidence["outcome"] != "unresolved"):
                raise ValidationError("conflicting completed proposal resolutions")
            if previous is None or previous == "unresolved":
                outcomes[proposal_path] = evidence["outcome"]
            if len(outcomes) > 10000:
                raise ValidationError("resolution outcome inventory exceeds 10000 entries")
    return outcomes
