import pytest
from unittest.mock import MagicMock
from acme.dns_challenge import _dns_provider_registry, CloudflareDnsProvider, Route53DnsProvider, GoogleCloudDnsProvider

class DummySettings:
    CLOUDFLARE_API_TOKEN = "token"
    CLOUDFLARE_ZONE_ID = "zone"
    AWS_ROUTE53_HOSTED_ZONE_ID = "hostedzone"
    AWS_REGION = "us-east-1"
    AWS_ACCESS_KEY_ID = "keyid"
    AWS_SECRET_ACCESS_KEY = "secret"
    GOOGLE_PROJECT_ID = "project"
    GOOGLE_CLOUD_DNS_ZONE_NAME = "zone"
    GOOGLE_APPLICATION_CREDENTIALS = "creds.json"

def test_registry_cloudflare():
    pytest.importorskip("cloudflare", reason="cloudflare SDK not installed; run: uv sync --extra dns-cloudflare")
    instance = _dns_provider_registry("cloudflare", DummySettings)
    assert isinstance(instance, CloudflareDnsProvider)
    assert instance._api_token == DummySettings.CLOUDFLARE_API_TOKEN
    assert instance._explicit_zone_id == DummySettings.CLOUDFLARE_ZONE_ID

def test_registry_route53():
    pytest.importorskip("boto3", reason="boto3 not installed; run: uv sync --extra dns-route53")
    instance = _dns_provider_registry("route53", DummySettings)
    assert isinstance(instance, Route53DnsProvider)
    assert instance._explicit_zone_id == DummySettings.AWS_ROUTE53_HOSTED_ZONE_ID
    assert instance._region == DummySettings.AWS_REGION
    assert instance._access_key_id == DummySettings.AWS_ACCESS_KEY_ID
    assert instance._secret_access_key == DummySettings.AWS_SECRET_ACCESS_KEY

def test_registry_google():
    pytest.importorskip("google.cloud.dns", reason="google-cloud-dns not installed; run: uv sync --extra dns-google")
    instance = _dns_provider_registry("google", DummySettings)
    assert isinstance(instance, GoogleCloudDnsProvider)
    assert instance._project_id == DummySettings.GOOGLE_PROJECT_ID
    assert instance._zone_name == DummySettings.GOOGLE_CLOUD_DNS_ZONE_NAME
    assert instance._credentials_path == DummySettings.GOOGLE_APPLICATION_CREDENTIALS

def test_registry_invalid():
    with pytest.raises(ValueError) as exc:
        _dns_provider_registry("invalid", DummySettings)
    assert "Unknown DNS_PROVIDER" in str(exc.value)
