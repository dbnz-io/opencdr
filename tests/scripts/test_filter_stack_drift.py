from scripts.filter_stack_drift import (
    is_expected_api_gateway_normalization,
    partition_drifts,
)


def cors_normalization(**overrides):
    drift = {
        "LogicalResourceId": "ApiGatewayMethodStatusOptions",
        "ResourceType": "AWS::ApiGateway::Method",
        "StackResourceDriftStatus": "MODIFIED",
        "PropertyDifferences": [
            {
                "PropertyPath": "/Integration/IntegrationResponses/0/ResponseTemplates",
                "ExpectedValue": '{"application/json":""}',
                "ActualValue": "null",
                "DifferenceType": "REMOVE",
            }
        ],
    }
    drift.update(overrides)
    return drift


def test_exact_generated_cors_normalization_is_ignored():
    assert is_expected_api_gateway_normalization(cors_normalization())


def test_non_options_method_is_actionable():
    assert not is_expected_api_gateway_normalization(
        cors_normalization(LogicalResourceId="ApiGatewayMethodStatusGet")
    )


def test_additional_difference_makes_the_resource_actionable():
    drift = cors_normalization()
    drift["PropertyDifferences"].append(
        {
            "PropertyPath": "/AuthorizationType",
            "ExpectedValue": "AWS_IAM",
            "ActualValue": "NONE",
            "DifferenceType": "NOT_EQUAL",
        }
    )

    assert not is_expected_api_gateway_normalization(drift)


def test_partition_keeps_real_drift_visible():
    expected = cors_normalization()
    actionable = {
        "LogicalResourceId": "ResponderIamRoleLambdaExecution",
        "ResourceType": "AWS::IAM::Role",
        "PropertyDifferences": [
            {
                "PropertyPath": "/Policies/0/PolicyDocument",
                "DifferenceType": "NOT_EQUAL",
            }
        ],
    }

    ignored, remaining = partition_drifts([expected, actionable])

    assert ignored == [expected]
    assert remaining == [actionable]
