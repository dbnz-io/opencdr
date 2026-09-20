"""Keep numeric values numeric across DynamoDB and JSON boundaries."""
from decimal import Decimal


def dynamodb_safe(value):
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {key: dynamodb_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [dynamodb_safe(item) for item in value]
    return value


def json_default(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    raise TypeError(f"Cannot serialize {type(value).__name__} as JSON")
