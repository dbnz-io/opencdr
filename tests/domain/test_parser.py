import pytest

from src.domain.ocsf_min_parser import (
    CloudTrailEventBridgeParser,
    GuardDutyEventBridgeParser,
    NormalizedEvent,
    build_default_router,
)

# ----------------------------
# Fixtures — realistic EventBridge payloads
# ----------------------------

CLOUDTRAIL_CREATE_USER = {
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.09",
        "eventTime": "2026-02-14T12:34:56Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "1.2.3.4",
        "userAgent": "aws-cli/2.x",
        "eventID": "event-id-abc123",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDABC123",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "userName": "alice",
        },
        "requestParameters": {"userName": "new-user"},
    },
}

CLOUDTRAIL_CONSOLE_LOGIN = {
    "detail-type": "AWS Console Sign In via CloudTrail",
    "source": "aws.signin",
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {
        "eventTime": "2026-02-14T12:34:56Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "5.6.7.8",
        "userAgent": "Mozilla/5.0",
        "eventID": "login-event-123",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDABC456",
            "arn": "arn:aws:iam::123456789012:user/bob",
            "userName": "bob",
        },
    },
}

CLOUDTRAIL_ASSUMED_ROLE = {
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.s3",
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {
        "eventTime": "2026-02-14T13:00:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "9.9.9.9",
        "userAgent": "aws-sdk-java",
        "eventID": "assumed-role-event-001",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROABC123:session-name",
            "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROABC123",
                    "arn": "arn:aws:iam::123456789012:role/MyRole",
                    "accountId": "123456789012",
                    "userName": "MyRole",
                }
            },
        },
    },
}

CLOUDTRAIL_WITH_ERROR = {
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {
        "eventTime": "2026-02-14T12:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "2.2.2.2",
        "eventID": "error-event-001",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "principalId": "XYZ", "userName": "charlie"},
        "errorCode": "EntityAlreadyExists",
        "errorMessage": "User already exists.",
    },
}

GUARDDUTY_FINDING = {
    "source": "aws.guardduty",
    "detail-type": "GuardDuty Finding",
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {
        "id": "gd-finding-id-001",
        "type": "Recon:IAMUser/MaliciousIPCaller",
        "severity": 8.0,
        "accountId": "123456789012",
        "createdAt": "2026-02-14T12:00:00Z",
        "updatedAt": "2026-02-14T12:30:00Z",
        "resource": {
            "accessKeyDetails": {
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "userName": "suspicious-user",
                "principalId": "AIDABC789",
            }
        },
        "service": {
            "action": {
                "awsApiCallAction": {
                    "remoteIpDetails": {"ipAddressV4": "9.10.11.12"},
                    "userAgent": "aws-sdk-python",
                }
            }
        },
    },
}

GUARDDUTY_EC2_FINDING = {
    "source": "aws.guardduty",
    "detail-type": "GuardDuty Finding",
    "account": "123456789012",
    "region": "us-west-2",
    "detail": {
        "id": "gd-ec2-finding-001",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": 5.0,
        "accountId": "123456789012",
        "createdAt": "2026-02-14T11:00:00Z",
        "updatedAt": "2026-02-14T11:30:00Z",
        "resource": {
            "instanceDetails": {"instanceId": "i-0abcdef1234567890"},
        },
        "service": {
            "action": {
                "networkConnectionAction": {
                    "remoteIpDetails": {"ipAddressV4": "20.21.22.23"},
                }
            }
        },
    },
}


# ----------------------------
# can_parse
# ----------------------------


class TestCanParse:
    def test_cloudtrail_api_call_accepted(self):
        assert CloudTrailEventBridgeParser().can_parse(CLOUDTRAIL_CREATE_USER)

    def test_cloudtrail_console_login_accepted(self):
        assert CloudTrailEventBridgeParser().can_parse(CLOUDTRAIL_CONSOLE_LOGIN)

    def test_guardduty_finding_accepted(self):
        assert GuardDutyEventBridgeParser().can_parse(GUARDDUTY_FINDING)

    def test_cloudtrail_parser_rejects_guardduty(self):
        assert not CloudTrailEventBridgeParser().can_parse(GUARDDUTY_FINDING)

    def test_guardduty_parser_rejects_cloudtrail(self):
        assert not GuardDutyEventBridgeParser().can_parse(CLOUDTRAIL_CREATE_USER)

    def test_unknown_event_rejected_by_all(self):
        unknown = {"detail-type": "Something Else", "source": "aws.unknown", "detail": {}}
        assert not CloudTrailEventBridgeParser().can_parse(unknown)
        assert not GuardDutyEventBridgeParser().can_parse(unknown)

    def test_cloudtrail_missing_event_name_rejected(self):
        bad = {**CLOUDTRAIL_CREATE_USER, "detail": {"eventSource": "iam.amazonaws.com"}}
        assert not CloudTrailEventBridgeParser().can_parse(bad)


# ----------------------------
# Router
# ----------------------------


class TestParserRouter:
    def test_router_routes_cloudtrail(self):
        result = build_default_router().parse(CLOUDTRAIL_CREATE_USER)
        assert result is not None
        assert isinstance(result, NormalizedEvent)

    def test_router_routes_guardduty(self):
        result = build_default_router().parse(GUARDDUTY_FINDING)
        assert result is not None
        assert isinstance(result, NormalizedEvent)

    def test_router_returns_none_for_unknown_event(self):
        unknown = {"detail-type": "Nothing", "source": "custom", "detail": {}}
        assert build_default_router().parse(unknown) is None


# ----------------------------
# CloudTrail parser
# ----------------------------


class TestCloudTrailParser:
    def setup_method(self):
        self.parser = CloudTrailEventBridgeParser()

    def test_source_is_cloudtrail(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.source == "cloudtrail"

    def test_activity_name(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.activity_name == "CreateUser"

    def test_category_derived_from_service(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.category == "iam"

    def test_class_name_api_activity(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.class_name == "api_activity"

    def test_actor_user_name(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.actor.user_name == "alice"

    def test_actor_arn(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.actor.arn == "arn:aws:iam::123456789012:user/alice"

    def test_actor_type(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.actor.type == "IAMUser"

    def test_network_source_ip(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.network.source_ip == "1.2.3.4"

    def test_network_user_agent(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.network.user_agent == "aws-cli/2.x"

    def test_api_service(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.api.service == "iam.amazonaws.com"

    def test_api_operation(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.api.operation == "CreateUser"

    def test_cloud_region(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.cloud_region == "us-east-1"

    def test_cloud_account_id(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.cloud_account_id == "123456789012"

    def test_event_id_uses_cloudtrail_event_id(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.event_id == "event-id-abc123"

    def test_event_id_is_stable(self):
        """Same input must always produce the same event_id."""
        r1 = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        r2 = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert r1.event_id == r2.event_id

    def test_raw_event_preserved(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.raw_event == CLOUDTRAIL_CREATE_USER

    def test_resource_extracted_from_request_parameters(self):
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        types = [r.type for r in result.resources]
        assert "AWS::IAM::User" in types

    def test_console_login_class_name(self):
        result = self.parser.parse(CLOUDTRAIL_CONSOLE_LOGIN)
        assert result.class_name == "authentication"

    def test_console_login_category(self):
        result = self.parser.parse(CLOUDTRAIL_CONSOLE_LOGIN)
        assert result.category == "authn"

    def test_error_code_populated(self):
        result = self.parser.parse(CLOUDTRAIL_WITH_ERROR)
        assert result.api.error_code == "EntityAlreadyExists"

    def test_error_message_populated(self):
        result = self.parser.parse(CLOUDTRAIL_WITH_ERROR)
        assert result.api.error_message == "User already exists."

    def test_assumed_role_actor_type(self):
        result = self.parser.parse(CLOUDTRAIL_ASSUMED_ROLE)
        assert result.actor.type == "AssumedRole"

    def test_assumed_role_user_name_from_session_issuer(self):
        """For AssumedRole, user_name should fall back to sessionContext.sessionIssuer.userName."""
        result = self.parser.parse(CLOUDTRAIL_ASSUMED_ROLE)
        assert result.actor.user_name == "MyRole"

    def test_cloudtrail_severity_is_unknown(self):
        """CloudTrail events carry no severity — should always be UNKNOWN."""
        result = self.parser.parse(CLOUDTRAIL_CREATE_USER)
        assert result.severity == "UNKNOWN"

    def test_event_id_falls_back_to_hash_when_no_cloudtrail_id(self):
        event = {**CLOUDTRAIL_CREATE_USER}
        event["detail"] = {k: v for k, v in event["detail"].items() if k != "eventID"}
        result = self.parser.parse(event)
        assert result.event_id is not None
        assert len(result.event_id) > 0

    def test_hash_event_id_is_stable(self):
        event = {**CLOUDTRAIL_CREATE_USER}
        event["detail"] = {k: v for k, v in event["detail"].items() if k != "eventID"}
        r1 = self.parser.parse(event)
        r2 = self.parser.parse(event)
        assert r1.event_id == r2.event_id


# ----------------------------
# GuardDuty parser
# ----------------------------


class TestGuardDutyParser:
    def setup_method(self):
        self.parser = GuardDutyEventBridgeParser()

    def test_source_is_guardduty(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.source == "guardduty"

    def test_activity_name_is_finding_type(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.activity_name == "Recon:IAMUser/MaliciousIPCaller"

    def test_category_is_threat(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.category == "threat"

    def test_class_name_is_security_finding(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.class_name == "security_finding"

    def test_severity_numeric_high(self):
        """8.0 should normalize to HIGH."""
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.severity == "HIGH"

    def test_severity_numeric_medium(self):
        """5.0 should normalize to MEDIUM."""
        result = self.parser.parse(GUARDDUTY_EC2_FINDING)
        assert result.severity == "MEDIUM"

    def test_event_id_uses_finding_id(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.event_id == "gd-finding-id-001"

    def test_event_id_is_stable(self):
        r1 = self.parser.parse(GUARDDUTY_FINDING)
        r2 = self.parser.parse(GUARDDUTY_FINDING)
        assert r1.event_id == r2.event_id

    def test_actor_user_name_from_access_key_details(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.actor.user_name == "suspicious-user"

    def test_network_source_ip_from_api_call_action(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.network.source_ip == "9.10.11.12"

    def test_network_source_ip_from_network_connection_action(self):
        result = self.parser.parse(GUARDDUTY_EC2_FINDING)
        assert result.network.source_ip == "20.21.22.23"

    def test_ec2_resource_extracted(self):
        result = self.parser.parse(GUARDDUTY_EC2_FINDING)
        types = [r.type for r in result.resources]
        assert "AWS::EC2::Instance" in types
        ids = [r.id for r in result.resources]
        assert "i-0abcdef1234567890" in ids

    def test_iam_access_key_resource_extracted(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        types = [r.type for r in result.resources]
        assert "AWS::IAM::AccessKey" in types

    def test_cloud_account_id(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.cloud_account_id == "123456789012"

    def test_cloud_region(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.cloud_region == "us-east-1"

    def test_raw_event_preserved(self):
        result = self.parser.parse(GUARDDUTY_FINDING)
        assert result.raw_event == GUARDDUTY_FINDING


# ----------------------------
# Severity normalization
# ----------------------------


class TestGuardDutyParser:
    def test_parses_finding_id_as_event_id(self):
        result = GuardDutyEventBridgeParser().parse(GUARDDUTY_FINDING)
        assert result.event_id == GUARDDUTY_FINDING["detail"]["id"]

    def test_parses_finding_type_as_activity_name(self):
        result = GuardDutyEventBridgeParser().parse(GUARDDUTY_FINDING)
        assert result.activity_name == GUARDDUTY_FINDING["detail"]["type"]

    def test_source_is_guardduty(self):
        result = GuardDutyEventBridgeParser().parse(GUARDDUTY_FINDING)
        assert result.source == "guardduty"

    def test_category_is_threat(self):
        result = GuardDutyEventBridgeParser().parse(GUARDDUTY_FINDING)
        assert result.category == "threat"

    def test_extracts_instance_resource(self):
        event = {
            **GUARDDUTY_FINDING,
            "detail": {
                **GUARDDUTY_FINDING["detail"],
                "resource": {"instanceDetails": {"instanceId": "i-abc123"}},
            },
        }
        result = GuardDutyEventBridgeParser().parse(event)
        assert any(r.id == "i-abc123" for r in result.resources)

    def test_extracts_access_key_resource(self):
        event = {
            **GUARDDUTY_FINDING,
            "detail": {
                **GUARDDUTY_FINDING["detail"],
                "resource": {"accessKeyDetails": {"accessKeyId": "AKIA123", "userName": "bob"}},
            },
        }
        result = GuardDutyEventBridgeParser().parse(event)
        resource_ids = [r.id for r in result.resources]
        assert "AKIA123" in resource_ids
        assert "bob" in resource_ids

    def test_extracts_actor_from_access_key_details(self):
        event = {
            **GUARDDUTY_FINDING,
            "detail": {
                **GUARDDUTY_FINDING["detail"],
                "resource": {"accessKeyDetails": {"accessKeyId": "AKIA123", "userName": "carol"}},
            },
        }
        result = GuardDutyEventBridgeParser().parse(event)
        assert result.actor.user_name == "carol"

    def test_generates_hash_id_when_no_finding_id(self):
        event = {
            **GUARDDUTY_FINDING,
            "detail": {k: v for k, v in GUARDDUTY_FINDING["detail"].items() if k != "id"},
        }
        result = GuardDutyEventBridgeParser().parse(event)
        assert result.event_id  # some hash was generated

    def test_can_parse_rejects_non_guardduty_source(self):
        event = {**GUARDDUTY_FINDING, "source": "aws.cloudtrail"}
        assert not GuardDutyEventBridgeParser().can_parse(event)

    def test_can_parse_rejects_wrong_detail_type(self):
        event = {**GUARDDUTY_FINDING, "detail-type": "Something Else"}
        assert not GuardDutyEventBridgeParser().can_parse(event)


class TestCloudTrailResources:
    def test_extracts_resources_list_from_cloudtrail(self):
        event = {
            **CLOUDTRAIL_CREATE_USER,
            "detail": {
                **CLOUDTRAIL_CREATE_USER["detail"],
                "resources": [{"ARN": "arn:aws:iam::123:user/bob", "type": "AWS::IAM::User"}],
            },
        }
        result = CloudTrailEventBridgeParser().parse(event)
        assert any(r.id == "arn:aws:iam::123:user/bob" for r in result.resources)

    def test_extracts_role_name_from_request_parameters(self):
        event = {
            **CLOUDTRAIL_CREATE_USER,
            "detail": {
                **CLOUDTRAIL_CREATE_USER["detail"],
                "requestParameters": {"roleName": "my-role"},
            },
        }
        result = CloudTrailEventBridgeParser().parse(event)
        assert any(r.id == "my-role" for r in result.resources)

    def test_extracts_bucket_name_from_request_parameters(self):
        event = {
            **CLOUDTRAIL_CREATE_USER,
            "detail": {
                **CLOUDTRAIL_CREATE_USER["detail"],
                "requestParameters": {"bucketName": "my-bucket"},
            },
        }
        result = CloudTrailEventBridgeParser().parse(event)
        assert any(r.id == "my-bucket" for r in result.resources)


class TestNormalizeSeverity:
    """
    Tests for _normalize_severity via the GuardDuty parser,
    since the function is module-private.
    """

    @pytest.mark.parametrize(
        "severity_value,expected",
        [
            (8.0, "HIGH"),
            (9.5, "HIGH"),
            (5.0, "MEDIUM"),
            (7.9, "MEDIUM"),
            (1.0, "LOW"),
            (4.9, "LOW"),
            (0.0, "INFO"),
            ("HIGH", "HIGH"),
            ("MEDIUM", "MEDIUM"),
            ("LOW", "LOW"),
            ("INFORMATIONAL", "INFO"),
            (None, "UNKNOWN"),
            ("8.0", "HIGH"),   # numeric-as-string path
            ("5.0", "MEDIUM"),
            ("invalid", "UNKNOWN"),
        ],
    )
    def test_severity_values(self, severity_value, expected):
        event = {
            **GUARDDUTY_FINDING,
            "detail": {**GUARDDUTY_FINDING["detail"], "severity": severity_value},
        }
        result = GuardDutyEventBridgeParser().parse(event)
        assert result.severity == expected
