from unittest.mock import MagicMock, patch

from boto3.dynamodb.types import TypeSerializer

from src.infra.detection_lists_repository import load_detection_lists

_serializer = TypeSerializer()


def _typed(item):
    return {key: _serializer.serialize(value) for key, value in item.items()}


def test_loads_active_version_snapshot_from_dedicated_table():
    aws = MagicMock()
    aws._ddb.query.side_effect = [
        {
            "Items": [
                _typed(
                    {
                        "list_id": "corp",
                        "item_key": "META",
                        "item_type": "METADATA",
                        "matcher": "cidr",
                        "value_type": "cidr",
                        "active_version": 4,
                        "active_version_id": "v-token",
                    }
                )
            ]
        },
        {
            "Items": [
                _typed(
                    {
                        "list_id": "corp",
                        "item_key": "VERSION#v-token#VALUE#abc",
                        "value": "10.0.0.0/8",
                    }
                )
            ]
        },
    ]
    with patch.dict("os.environ", {"DETECTION_LISTS_TABLE_NAME": "lists"}):
        result = load_detection_lists(aws, MagicMock())
    assert result == {
        "corp": {
            "matcher": "cidr",
            "value_type": "cidr",
            "version": 4,
            "values": ["10.0.0.0/8"],
        }
    }


def test_empty_active_version_is_omitted_to_make_not_in_list_fail_closed():
    aws = MagicMock()
    aws._ddb.query.side_effect = [
        {
            "Items": [
                _typed(
                    {
                        "list_id": "broken",
                        "item_key": "META",
                        "item_type": "METADATA",
                        "active_version": 1,
                        "active_version_id": "missing",
                    }
                )
            ]
        },
        {"Items": []},
    ]
    with patch.dict("os.environ", {"DETECTION_LISTS_TABLE_NAME": "lists"}):
        result = load_detection_lists(aws, MagicMock(), legacy_fallback=False)
    assert result == {}
