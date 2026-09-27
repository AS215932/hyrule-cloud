"""Callback configuration must fail before API/worker startup can take payment."""
import pytest
from pydantic import ValidationError

from hyrule_cloud.config import HyruleConfig


@pytest.mark.parametrize('value', [
    '', 'http://cloud.hyrule.host', 'ftp://cloud.hyrule.host', 'https://',
    'https://user:fixture@cloud.hyrule.host', 'https://cloud.hyrule.host?key=fixture',
    'https://cloud.hyrule.host#fragment', 'https://cloud.hyrule.host:invalid',
    ' https://cloud.hyrule.host', 'https://cloud.hyrule.host/with space',
])
def test_invalid_callback_base_blocks_configuration(value, monkeypatch):
    monkeypatch.setenv('HYRULE_PUBLIC_BASE_URL', value)
    with pytest.raises(ValidationError):
        HyruleConfig(_env_file=None)


@pytest.mark.parametrize(('value', 'expected'), [
    ('https://cloud.hyrule.host', 'https://cloud.hyrule.host'),
    ('https://cloud.hyrule.host/', 'https://cloud.hyrule.host'),
    ('https://staging.hyrule.host:8443/api/', 'https://staging.hyrule.host:8443/api'),
])
def test_valid_https_callback_bases_are_normalized(value, expected):
    assert HyruleConfig(public_base_url=value, _env_file=None).public_base_url == expected
