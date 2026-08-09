import copy
import json

import pytest

from weflow_chat.validator.result import (
    ValidationResultError,
    read_avatar_aggregate_result,
)


def _aggregate_payload():
    return {
        "version": 1,
        "candidateContactCount": 4,
        "avatarUrlCount": 2,
        "headImageBufferCount": 2,
        "finalAvatarCount": 3,
        "missingAvatarCount": 1,
        "reasonCounts": {
            "urlOnly": 1,
            "headImageBufferOnly": 1,
            "urlAndHeadImageBuffer": 1,
            "noSupportedSource": 1,
        },
    }


def _write_payload(tmp_path, payload):
    path = tmp_path / "avatar-aggregate.json"
    path.write_text(
        json.dumps(payload, separators=(",", ":")),
        encoding="utf-8",
    )
    return path


def test_avatar_aggregate_result_accepts_only_aggregate_counts(tmp_path):
    payload = _aggregate_payload()
    assert read_avatar_aggregate_result(
        _write_payload(tmp_path, payload)
    ) == payload


def test_avatar_aggregate_result_rejects_schema_and_reason_key_drift(
    tmp_path,
):
    payload = _aggregate_payload()
    payload["identifier"] = "synthetic-contact"
    with pytest.raises(
        ValidationResultError, match="^avatar_aggregate_schema_mismatch$"
    ):
        read_avatar_aggregate_result(_write_payload(tmp_path, payload))

    payload = _aggregate_payload()
    del payload["missingAvatarCount"]
    with pytest.raises(
        ValidationResultError, match="^avatar_aggregate_schema_mismatch$"
    ):
        read_avatar_aggregate_result(_write_payload(tmp_path, payload))

    payload = copy.deepcopy(_aggregate_payload())
    payload["reasonCounts"]["networkFailure"] = 0
    with pytest.raises(
        ValidationResultError, match="^avatar_aggregate_schema_mismatch$"
    ):
        read_avatar_aggregate_result(_write_payload(tmp_path, payload))


@pytest.mark.parametrize(
    ("field", "detail"),
    (
        ("identifier", "synthetic-contact"),
        ("avatarUrl", "https://example.invalid/avatar"),
        ("sourcePath", r"X:\synthetic\avatar.jpg"),
        ("imageData", "data:image/jpeg;base64,AA=="),
        ("decryptKey", "synthetic-key"),
        ("sql", "SELECT synthetic"),
        ("stack", "synthetic stack trace"),
    ),
)
def test_avatar_aggregate_result_rejects_every_forbidden_detail_class(
    tmp_path, field, detail
):
    payload = _aggregate_payload()
    payload[field] = detail
    with pytest.raises(
        ValidationResultError, match="^avatar_aggregate_schema_mismatch$"
    ):
        read_avatar_aggregate_result(_write_payload(tmp_path, payload))

    payload = _aggregate_payload()
    payload["candidateContactCount"] = detail
    with pytest.raises(
        ValidationResultError, match="^avatar_aggregate_schema_mismatch$"
    ):
        read_avatar_aggregate_result(_write_payload(tmp_path, payload))


def test_avatar_aggregate_result_requires_version_one_and_safe_counts(
    tmp_path,
):
    for field, value in (
        ("candidateContactCount", -1),
        ("avatarUrlCount", 0.5),
        ("headImageBufferCount", 2**53),
        ("finalAvatarCount", True),
        ("missingAvatarCount", None),
    ):
        payload = _aggregate_payload()
        payload[field] = value
        with pytest.raises(
            ValidationResultError,
            match="^avatar_aggregate_schema_mismatch$",
        ):
            read_avatar_aggregate_result(_write_payload(tmp_path, payload))

    payload = _aggregate_payload()
    payload["version"] = 2
    with pytest.raises(
        ValidationResultError, match="^avatar_aggregate_schema_mismatch$"
    ):
        read_avatar_aggregate_result(_write_payload(tmp_path, payload))

    payload = copy.deepcopy(_aggregate_payload())
    payload["reasonCounts"]["urlOnly"] = -1
    with pytest.raises(
        ValidationResultError, match="^avatar_aggregate_schema_mismatch$"
    ):
        read_avatar_aggregate_result(_write_payload(tmp_path, payload))


def test_avatar_aggregate_result_enforces_the_exact_coverage_partition(
    tmp_path,
):
    for field in (
        "candidateContactCount",
        "avatarUrlCount",
        "headImageBufferCount",
        "finalAvatarCount",
        "missingAvatarCount",
    ):
        payload = _aggregate_payload()
        payload[field] = 5
        with pytest.raises(
            ValidationResultError,
            match="^avatar_aggregate_count_mismatch$",
        ):
            read_avatar_aggregate_result(_write_payload(tmp_path, payload))

    payload = copy.deepcopy(_aggregate_payload())
    payload["reasonCounts"]["urlOnly"] = 2
    with pytest.raises(
        ValidationResultError,
        match="^avatar_aggregate_count_mismatch$",
    ):
        read_avatar_aggregate_result(_write_payload(tmp_path, payload))
