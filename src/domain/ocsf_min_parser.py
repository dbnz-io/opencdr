# src/domain/parsing/ocsf_min_parser.py
#
# Minimal, OCSF-aligned normalization for:
# - CloudTrail events delivered via EventBridge ("AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail")
# - GuardDuty findings delivered via EventBridge ("GuardDuty Finding")
#
# Design goals:
# - Keep a small, stable internal contract (NormalizedEvent)
# - Keep it OCSF-aligned (naming + concepts), but NOT full OCSF complexity
# - Preserve the original AWS payload in `raw_event` for fidelity/debugging
#
# You can later add:
# - full OCSF class mapping + type_uid
# - schema registry / rule schemas in DynamoDB
# - more connectors (VPC Flow Logs, ALB logs, etc.)

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

# ----------------------------
# Utilities
# ----------------------------


def _iso_utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_get(d: Any, *path: str, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default


def _to_iso_z(dt_str: str | None) -> str | None:
    """
    CloudTrail uses "eventTime" like "2026-02-14T12:34:56Z".
    GuardDuty uses ISO8601 with Z too.
    We keep it as given if it looks ISO; otherwise return as-is.
    """
    if not dt_str:
        return None
    return dt_str


def _hash_id(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        if p is None:
            p = ""
        h.update(p.encode("utf-8"))
        h.update(b"|")
    return h.hexdigest()[:32]  # short but collision-resistant enough for ids


def _coalesce(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        return v
    return None


def _normalize_severity(sev: Any) -> str:
    """
    Return one of: CRITICAL/HIGH/MEDIUM/LOW/INFO/UNKNOWN.
    CloudTrail doesn't have severity; GuardDuty does.
    """
    if sev is None:
        return "UNKNOWN"
    if isinstance(sev, str):
        s = sev.strip().upper()
        # GuardDuty: "HIGH", "MEDIUM", "LOW"
        if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"):
            return "INFO" if s == "INFORMATIONAL" else s
        # Sometimes numeric-as-string
        try:
            sev_num = float(s)
            return _normalize_severity(sev_num)
        except Exception:
            return "UNKNOWN"
    if isinstance(sev, (int, float)):
        # Simple numeric bucketing (optional; adjust later)
        if sev >= 8:
            return "HIGH"
        if sev >= 5:
            return "MEDIUM"
        if sev > 0:
            return "LOW"
        return "INFO"
    return "UNKNOWN"


# ----------------------------
# Minimal OCSF-aligned model
# ----------------------------


@dataclass(frozen=True)
class Actor:
    # OCSF-ish: actor.user / actor.user.name, actor.user.uid, actor.session, etc.
    user_name: str | None = None
    user_id: str | None = None  # e.g., principalId
    account_id: str | None = None
    arn: str | None = None
    type: str | None = None  # Root/IAMUser/AssumedRole/FederatedUser/Unknown
    session_arn: str | None = None  # assumed role session ARN if applicable


@dataclass(frozen=True)
class ApiCall:
    # OCSF-ish: api.operation, api.service, api.request, api.response, etc.
    service: str | None = None  # e.g., iam.amazonaws.com (CloudTrail eventSource)
    operation: str | None = None  # e.g., CreateUser (CloudTrail eventName)
    region: str | None = None
    http_status: int | None = None
    error_code: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class Network:
    # OCSF-ish: src_endpoint.ip, user_agent, etc.
    source_ip: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True)
class ResourceRef:
    # Small generic resource reference, OCSF-ish "resources"
    type: str | None = None  # "AWS::IAM::User", "AWS::S3::Bucket", etc (best-effort)
    id: str | None = None  # ARN or resource id/name
    name: str | None = None  # optional friendly name


@dataclass(frozen=True)
class NormalizedEvent:
    """
    Minimal OCSF-aligned envelope for CDR.
    """

    # Identity + uniqueness
    event_id: str  # stable hash for idempotency/correlation
    source: str  # "cloudtrail" | "guardduty"
    time: str  # ISO8601 time of event/finding

    # OCSF-ish classification (minimal)
    category: str  # e.g., "iam", "authn", "network", "malware", "threat"
    class_name: str  # e.g., "api_activity", "authentication", "security_finding"
    activity_name: str  # e.g., "CreateUser", "ConsoleLogin", "Recon:IAMUser/PasswordBruteForce"

    # Severity (engine-friendly)
    severity: str = "UNKNOWN"  # CRITICAL/HIGH/MEDIUM/LOW/INFO/UNKNOWN

    # Core context
    actor: Actor = field(default_factory=Actor)
    api: ApiCall = field(default_factory=ApiCall)
    network: Network = field(default_factory=Network)
    resources: list[ResourceRef] = field(default_factory=list)

    # Cloud context
    cloud_provider: str = "aws"
    cloud_account_id: str | None = None
    cloud_region: str | None = None

    # Raw payload (keep fidelity)
    raw_event: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----------------------------
# Parser Protocol + Router
# ----------------------------


class Parser(Protocol):
    def can_parse(self, event: dict[str, Any]) -> bool: ...
    def parse(self, event: dict[str, Any]) -> NormalizedEvent | None: ...


class ParserRouter:
    def __init__(self, parsers: list[Parser]):
        self.parsers = parsers

    def parse(self, event: dict[str, Any]) -> NormalizedEvent | None:
        for p in self.parsers:
            if p.can_parse(event):
                return p.parse(event)
        return None


# ----------------------------
# CloudTrail via EventBridge
# ----------------------------


class CloudTrailEventBridgeParser:
    """
    Handles EventBridge envelopes containing CloudTrail detail.

    Typical patterns:
      detail-type: "AWS API Call via CloudTrail"
      detail-type: "AWS Console Sign In via CloudTrail"
    """

    CLOUDTRAIL_DETAIL_TYPES = {
        "AWS API Call via CloudTrail",
        "AWS Console Sign In via CloudTrail",
    }

    def can_parse(self, event: dict[str, Any]) -> bool:
        dt = event.get("detail-type")
        if dt not in self.CLOUDTRAIL_DETAIL_TYPES:
            return False
        detail = event.get("detail")
        return isinstance(detail, dict) and "eventName" in detail and "eventSource" in detail

    def parse(self, event: dict[str, Any]) -> NormalizedEvent | None:
        detail = event.get("detail") or {}

        event_source = _safe_get(detail, "eventSource")
        event_name = _safe_get(detail, "eventName")
        aws_region = _safe_get(detail, "awsRegion") or event.get("region")
        account_id = _safe_get(detail, "recipientAccountId") or event.get("account")
        event_time = _to_iso_z(_safe_get(detail, "eventTime")) or _iso_utc_now()

        user_agent = _safe_get(detail, "userAgent")
        source_ip = _safe_get(detail, "sourceIPAddress")

        http_status = _safe_get(detail, "responseElements", "status")  # not reliable
        # Better: CloudTrail uses errorCode/errorMessage when failed
        error_code = _safe_get(detail, "errorCode")
        error_message = _safe_get(detail, "errorMessage")

        # Identity
        ui = _safe_get(detail, "userIdentity", default={}) or {}
        actor_type = _safe_get(ui, "type")
        actor_arn = _safe_get(ui, "arn")
        principal_id = _safe_get(ui, "principalId")
        user_name = _coalesce(
            _safe_get(ui, "userName"),
            _safe_get(detail, "userIdentity", "sessionContext", "sessionIssuer", "userName"),
        )

        # Class/category (minimal)
        # - ConsoleLogin -> authentication
        # - everything else -> api_activity
        if event_name == "ConsoleLogin":
            class_name = "authentication"
            category = "authn"
        else:
            class_name = "api_activity"
            # crude category by service prefix
            category = (str(event_source).split(".")[0] if event_source else "aws").lower()

        activity_name = str(event_name) if event_name else "Unknown"

        # Build stable event_id for idempotency:
        # Use CloudTrail eventID if present; else hash key fields.
        ct_event_id = _safe_get(detail, "eventID")
        event_id = ct_event_id or _hash_id(
            "cloudtrail",
            account_id or "",
            aws_region or "",
            event_time,
            event_source or "",
            activity_name,
            principal_id or "",
            source_ip or "",
        )

        # Minimal resource extraction (best-effort; extend later)
        resources: list[ResourceRef] = []
        # CloudTrail sometimes includes "resources": [{"ARN": "...", "type": "..."}]
        ct_resources = _safe_get(detail, "resources")
        if isinstance(ct_resources, list):
            for r in ct_resources:
                if not isinstance(r, dict):
                    continue
                resources.append(
                    ResourceRef(
                        type=_safe_get(r, "type"),
                        id=_safe_get(r, "ARN") or _safe_get(r, "arn"),
                        name=_safe_get(r, "name"),
                    )
                )

        # If no resources, try a couple common requestParameters (best-effort)
        rp = _safe_get(detail, "requestParameters", default={}) or {}
        if isinstance(rp, dict):
            # Common: userName, roleName, policyArn, bucketName, etc.
            if "userName" in rp and isinstance(rp.get("userName"), str):
                resources.append(
                    ResourceRef(
                        type="AWS::IAM::User", id=rp.get("userName"), name=rp.get("userName")
                    )
                )
            if "roleName" in rp and isinstance(rp.get("roleName"), str):
                resources.append(
                    ResourceRef(
                        type="AWS::IAM::Role", id=rp.get("roleName"), name=rp.get("roleName")
                    )
                )
            if "bucketName" in rp and isinstance(rp.get("bucketName"), str):
                resources.append(
                    ResourceRef(
                        type="AWS::S3::Bucket", id=rp.get("bucketName"), name=rp.get("bucketName")
                    )
                )

        # Severity: CloudTrail itself doesn't carry it; keep UNKNOWN here.
        severity = "UNKNOWN"

        return NormalizedEvent(
            event_id=event_id,
            source="cloudtrail",
            time=event_time,
            category=category,
            class_name=class_name,
            activity_name=activity_name,
            severity=severity,
            actor=Actor(
                user_name=user_name,
                user_id=principal_id,
                account_id=account_id,
                arn=actor_arn,
                type=actor_type,
            ),
            api=ApiCall(
                service=event_source,
                operation=activity_name,
                region=aws_region,
                http_status=http_status if isinstance(http_status, int) else None,
                error_code=error_code,
                error_message=error_message,
            ),
            network=Network(
                source_ip=source_ip,
                user_agent=user_agent,
            ),
            resources=resources,
            cloud_account_id=account_id,
            cloud_region=aws_region,
            raw_event=event,  # keep full EventBridge envelope for traceability
        )


# ----------------------------
# GuardDuty via EventBridge
# ----------------------------


class GuardDutyEventBridgeParser:
    """
    Handles EventBridge envelopes for GuardDuty findings.

    Typical:
      source: "aws.guardduty"
      detail-type: "GuardDuty Finding"
      detail: { id, type, severity, resource, ... }
    """

    def can_parse(self, event: dict[str, Any]) -> bool:
        if event.get("source") != "aws.guardduty":
            return False
        if event.get("detail-type") != "GuardDuty Finding":
            return False
        detail = event.get("detail")
        return isinstance(detail, dict) and "id" in detail and "type" in detail

    def parse(self, event: dict[str, Any]) -> NormalizedEvent | None:
        detail = event.get("detail") or {}

        finding_id = _safe_get(detail, "id")
        finding_type = _safe_get(detail, "type")
        severity_raw = _safe_get(detail, "severity")
        severity = _normalize_severity(severity_raw)

        account_id = _safe_get(detail, "accountId") or event.get("account")
        region = event.get("region")
        time_str = (
            _to_iso_z(_safe_get(detail, "updatedAt"))
            or _to_iso_z(_safe_get(detail, "createdAt"))
            or _iso_utc_now()
        )

        # Actor/network-ish context from GuardDuty depends on finding type
        # Best-effort extraction:
        src_ip = _safe_get(
            detail, "service", "action", "networkConnectionAction", "remoteIpDetails", "ipAddressV4"
        ) or _safe_get(
            detail, "service", "action", "awsApiCallAction", "remoteIpDetails", "ipAddressV4"
        )
        user_agent = _safe_get(detail, "service", "action", "awsApiCallAction", "userAgent")

        # Resource refs (best-effort)
        resources: list[ResourceRef] = []
        r = _safe_get(detail, "resource", default={}) or {}
        if isinstance(r, dict):
            # Common resource types include instanceDetails, accessKeyDetails, etc.
            inst_id = _safe_get(r, "instanceDetails", "instanceId")
            if inst_id:
                resources.append(ResourceRef(type="AWS::EC2::Instance", id=inst_id, name=inst_id))
            ak = _safe_get(r, "accessKeyDetails", "accessKeyId")
            if ak:
                resources.append(ResourceRef(type="AWS::IAM::AccessKey", id=ak, name=ak))
            uname = _safe_get(r, "accessKeyDetails", "userName")
            if uname:
                resources.append(ResourceRef(type="AWS::IAM::User", id=uname, name=uname))

        # OCSF-ish classification
        class_name = "security_finding"
        category = "threat"
        activity_name = str(finding_type) if finding_type else "GuardDutyFinding"

        # Build stable event_id (use finding id)
        event_id = (
            str(finding_id)
            if finding_id
            else _hash_id("guardduty", account_id or "", region or "", time_str, activity_name)
        )

        # Fill an Actor best-effort (GuardDuty may include accessKeyDetails/userName)
        actor_user = _safe_get(detail, "resource", "accessKeyDetails", "userName")
        actor_arn = _safe_get(
            detail, "resource", "accessKeyDetails", "principalId"
        )  # not ARN, but keep for now
        actor_id = _safe_get(detail, "resource", "accessKeyDetails", "accessKeyId")

        return NormalizedEvent(
            event_id=event_id,
            source="guardduty",
            time=time_str,
            category=category,
            class_name=class_name,
            activity_name=activity_name,
            severity=severity,
            actor=Actor(
                user_name=actor_user,
                user_id=actor_id,
                account_id=account_id,
                arn=actor_arn,
                type="GuardDuty",
            ),
            api=ApiCall(
                service="guardduty",
                operation=activity_name,
                region=region,
                error_code=None,
                error_message=None,
            ),
            network=Network(
                source_ip=src_ip,
                user_agent=user_agent,
            ),
            resources=resources,
            cloud_account_id=account_id,
            cloud_region=region,
            raw_event=event,
        )


# ----------------------------
# Factory
# ----------------------------


def build_default_router() -> ParserRouter:
    return ParserRouter(
        parsers=[
            CloudTrailEventBridgeParser(),
            GuardDutyEventBridgeParser(),
        ]
    )


# ----------------------------
# Example usage (keep out of prod handler)
# ----------------------------

if __name__ == "__main__":
    router = build_default_router()

    # Load from stdin or file during local tests
    sample = {
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "account": "123456789012",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.09",
            "eventTime": "2026-02-14T12:34:56Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "ABC",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "userName": "alice",
            },
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "aws-cli/2.x",
            "eventID": "abcd-1234",
            "requestParameters": {"userName": "evil-user"},
        },
    }

    ne = router.parse(sample)
    print(json.dumps(ne.to_dict() if ne else None, indent=2))
