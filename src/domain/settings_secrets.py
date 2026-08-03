# src/domain/settings_secrets.py
"""
Shared conventions for indirecting settings secrets (Slack/Discord webhook
URLs, the Jira API token, and custom webhook target headers) through SSM
Parameter Store instead of storing them as plain DynamoDB attributes.

Used by both api.py (write path -- externalizes real values to SSM,
storing only a reference) and notifier.py (read path -- resolves a
reference back to the real value at send time). Kept as its own module,
not duplicated in each handler, so the (channel, field) list and the
`ssm:` reference convention live in exactly one place.
"""
from __future__ import annotations

import os
from typing import Any

# (channel, field) pairs that hold plaintext credentials/secrets.
SECRET_CHANNEL_FIELDS: tuple[tuple[str, str], ...] = (
    ("slack", "webhook_url"),
    ("discord", "webhook_url"),
    ("jira", "api_token"),
)

_SSM_REF_PREFIX = "ssm:"


def is_ssm_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(_SSM_REF_PREFIX)


def ssm_param_name(setting_id: str, *parts: str) -> str:
    stage = os.getenv("STAGE", "dev")
    return f"/opencdr-{stage}/settings/{setting_id}/" + "/".join(parts)


def ssm_ref(param_name: str) -> str:
    return f"{_SSM_REF_PREFIX}{param_name}"


def ssm_ref_param_name(ref: str) -> str:
    return ref[len(_SSM_REF_PREFIX) :]


def iter_secret_locations(channels: Any) -> list[tuple[dict, str, tuple[str, ...]]]:
    """
    Yields (container, field_key, path_parts) for every secret slot present
    in a settings `channels` dict -- the 3 static channel fields plus any
    webhook target headers -- regardless of whether that slot currently
    holds a real value, an `ssm:` reference, or nothing. `container[field_key]`
    is the value to read/replace; `path_parts` builds the SSM parameter name.
    """
    locations: list[tuple[dict, str, tuple[str, ...]]] = []
    if not isinstance(channels, dict):
        return locations

    for channel_name, field_name in SECRET_CHANNEL_FIELDS:
        cfg = channels.get(channel_name)
        if isinstance(cfg, dict):
            locations.append((cfg, field_name, (channel_name, field_name)))

    webhook_cfg = channels.get("webhook")
    if isinstance(webhook_cfg, dict) and isinstance(webhook_cfg.get("targets"), list):
        for idx, target in enumerate(webhook_cfg["targets"]):
            if not isinstance(target, dict):
                continue
            headers = target.get("headers")
            if isinstance(headers, dict):
                for header_name in list(headers.keys()):
                    locations.append(
                        (headers, header_name, ("webhook", "targets", str(idx), "headers", header_name))
                    )

    return locations
