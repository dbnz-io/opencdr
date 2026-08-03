# src/config/requirements.py
"""
Per-Lambda configuration loaders.

Goal:
- Centralize env var reading + validation per Lambda role.
- Avoid one giant config.py that crashes other lambdas due to missing env vars.
- Keep config as DATA (no boto3 / no AWS clients).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Keep your constants here (or import them from a dedicated constants module)
ALLOWED_EVENT_TYPES: set[str] = {
    "INGESTION",
    "PROCESSING",
    "STORAGE",
    "NOTIFICATION",
    "SYSTEM",
    "SECURITY_EVENT",
    "ERROR",
}

ALLOWED_CONDITION_MODES: set[str] = {
    "exists",
    "not_exists",
    "in",
    "not_in",
    "matches",
    "not_matches",
    "contains",
    "not_contains",
    "prefix",
    "not_prefix",
    "suffix",
    "not_suffix",
}


def _getenv(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name, default)
    if v is None:
        return None
    v = v.strip()
    return v if v else None


def _require(name: str) -> str:
    v = _getenv(name)
    if not v:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return v


# -------------------------
# Config dataclasses
# -------------------------


@dataclass(frozen=True)
class BaseConfig:
    service: str
    stage: str
    region: str
    lambda_name: str


@dataclass(frozen=True)
class ProcessorConfig(BaseConfig):
    events_table_name: str
    detection_rules_table_name: str
    logs_table_name: str

    # In your MVP you send to SQS from processor; in outbox architecture
    # you may remove these requirements for processor.
    notifications_queue_url: str | None = None
    responses_queue_url: str | None = None

    # Optional (for later)
    outbox_table_name: str | None = None


@dataclass(frozen=True)
class NotifierConfig(BaseConfig):
    logs_table_name: str
    notifications_queue_url: str

    # Webhooks are optional (skip if unset)
    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None

    # Optional (for execution tracking later)
    executions_table_name: str | None = None


@dataclass(frozen=True)
class ResponderConfig(BaseConfig):
    logs_table_name: str
    responses_queue_url: str

    # Optional responder envs
    opencdr_ir_role_arn: str | None = None
    dredge_dry_run: str = "false"
    executions_table_name: str | None = None


@dataclass(frozen=True)
class ApiConfig(BaseConfig):
    logs_table_name: str
    detection_rules_table_name: str
    settings_table_name: str
    events_table_name: str


@dataclass(frozen=True)
class PublisherConfig(BaseConfig):
    logs_table_name: str
    outbox_table_name: str
    notifications_queue_url: str
    responses_queue_url: str
    # Optional: if publisher also marks things in a signals table, etc.
    # signals_table_name: Optional[str] = None


# -------------------------
# Shared base loader
# -------------------------


def _load_base(*, default_service: str = "OPENCDR") -> BaseConfig:
    return BaseConfig(
        service=_getenv("SERVICE_NAME", default_service) or default_service,
        stage=_getenv("STAGE", "dev") or "dev",
        region=_getenv("AWS_REGION", _getenv("REGION", "us-east-1") or "us-east-1") or "us-east-1",
        lambda_name=_getenv("LAMBDA_NAME", "unknown") or "unknown",
    )


# -------------------------
# Per-lambda loaders
# -------------------------


def load_processor_config(*, default_service: str = "OPENCDR") -> ProcessorConfig:
    base = _load_base(default_service=default_service)
    return ProcessorConfig(
        **base.__dict__,
        events_table_name=_require("EVENTS_TABLE_NAME"),
        detection_rules_table_name=_require("DETECTION_RULES_TABLE_NAME"),
        logs_table_name=_require("LOGS_TABLE_NAME"),
        notifications_queue_url=_getenv("NOTIFICATIONS_QUEUE_URL"),
        responses_queue_url=_getenv("RESPONSES_QUEUE_URL"),
        outbox_table_name=_getenv("OUTBOX_TABLE_NAME"),
    )


def load_notifier_config(*, default_service: str = "OPENCDR") -> NotifierConfig:
    base = _load_base(default_service=default_service)
    return NotifierConfig(
        **base.__dict__,
        logs_table_name=_require("LOGS_TABLE_NAME"),
        notifications_queue_url=_require("NOTIFICATIONS_QUEUE_URL"),
        slack_webhook_url=_getenv("SLACK_WEBHOOK_URL"),
        discord_webhook_url=_getenv("DISCORD_WEBHOOK_URL"),
        executions_table_name=_getenv("EXECUTIONS_TABLE_NAME"),
    )


def load_responder_config(*, default_service: str = "OPENCDR") -> ResponderConfig:
    base = _load_base(default_service=default_service)
    return ResponderConfig(
        **base.__dict__,
        logs_table_name=_require("LOGS_TABLE_NAME"),
        responses_queue_url=_require("RESPONSES_QUEUE_URL"),
        opencdr_ir_role_arn=_getenv("OPENCDR_IR_ROLE_ARN"),
        dredge_dry_run=_getenv("DREDGE_DRY_RUN", "false") or "false",
        executions_table_name=_getenv("EXECUTIONS_TABLE_NAME"),
    )


def load_api_config(*, default_service: str = "OPENCDR") -> ApiConfig:
    base = _load_base(default_service=default_service)
    return ApiConfig(
        **base.__dict__,
        logs_table_name=_require("LOGS_TABLE_NAME"),
        detection_rules_table_name=_require("DETECTION_RULES_TABLE_NAME"),
        settings_table_name=_require("SETTINGS_TABLE_NAME"),
        events_table_name=_require("EVENTS_TABLE_NAME"),
    )


def load_publisher_config(*, default_service: str = "OPENCDR") -> PublisherConfig:
    """
    For your future outbox publisher Lambda.
    """
    base = _load_base(default_service=default_service)
    return PublisherConfig(
        **base.__dict__,
        logs_table_name=_require("LOGS_TABLE_NAME"),
        outbox_table_name=_require("OUTBOX_TABLE_NAME"),
        notifications_queue_url=_require("NOTIFICATIONS_QUEUE_URL"),
        responses_queue_url=_require("RESPONSES_QUEUE_URL"),
    )
