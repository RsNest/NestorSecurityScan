"""Unit tests for image reference parsing."""

import pytest

from app.errors import ImageReferenceError
from app.services.image_ref import parse_image_reference


def test_parse_short_name():
    ref = parse_image_reference("alpine:3.20")
    assert ref.registry == "docker.io"
    assert ref.repository == "library/alpine"
    assert ref.tag == "3.20"
    assert ref.digest is None


def test_parse_digest():
    digest = "sha256:" + "a" * 64
    ref = parse_image_reference(f"harbor.example.ru/project/backend@{digest}")
    assert ref.registry == "harbor.example.ru"
    assert ref.repository == "project/backend"
    assert ref.digest == digest
    assert ref.reference_for_scan.endswith(f"@{digest}")


def test_reject_unsafe_chars():
    with pytest.raises(ImageReferenceError):
        parse_image_reference("alpine:3.20;rm -rf /")


def test_reject_path_traversal():
    with pytest.raises(ImageReferenceError):
        parse_image_reference("../evil:latest")
