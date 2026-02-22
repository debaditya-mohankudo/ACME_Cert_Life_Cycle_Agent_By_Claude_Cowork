"""
Unit tests for DNS-01 challenge support.

Tests cover:
  - compute_dns_txt_value() — SHA-256 correctness, determinism, known vector
  - make_dns_provider() — dispatch for all 3 providers, ImportError hints
  - CloudflareDnsProvider — create (explicit zone, auto-discover, idempotent), delete, error swallowed
  - Route53DnsProvider — UPSERT with "" wrapping, zone discovery, DELETE, error swallowed
  - GoogleCloudDnsProvider — create chain, delete chain, error swallowed
  - order_initializer with dns-01 — correct challenge selected, fields populated
  - challenge_setup DNS branch — create_txt_record called, propagation sleep behavior
  - _cleanup_challenge DNS branch — delete called, partial failure, safe when no provider
  - Config validation — dns mode accepted, missing token caught, existing modes unchanged

No Pebble or real DNS credentials required — all network calls are mocked.
"""
from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import MagicMock, call, patch

import pytest


# ─── compute_dns_txt_value ────────────────────────────────────────────────────


class TestComputeDnsTxtValue:
    """Tests for acme.dns_challenge.compute_dns_txt_value."""

    def test_known_vector(self):
        """RFC 8555 §8.4 example: SHA-256 of key_auth → base64url, no padding."""
        from acme.dns_challenge import compute_dns_txt_value

        key_auth = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA.nysaScAHF4R6FyQ7UGnL1hYu3Dg6EBKZ2TqkPl1JXIA"
        result = compute_dns_txt_value(key_auth)

        # Verify manually: base64url(SHA256(key_auth))
        expected_bytes = hashlib.sha256(key_auth.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(expected_bytes).rstrip(b"=").decode("ascii")
        assert result == expected

    def test_no_padding(self):
        """Result must not contain '=' padding characters."""
        from acme.dns_challenge import compute_dns_txt_value

        result = compute_dns_txt_value("token.thumbprint")
        assert "=" not in result

    def test_deterministic(self):
        """Same key_auth always produces the same TXT value."""
        from acme.dns_challenge import compute_dns_txt_value

        key_auth = "abc.def"
        assert compute_dns_txt_value(key_auth) == compute_dns_txt_value(key_auth)

    def test_different_inputs_produce_different_outputs(self):
        """Different key_auth strings must produce different TXT values."""
        from acme.dns_challenge import compute_dns_txt_value

        assert compute_dns_txt_value("token1.tp") != compute_dns_txt_value("token2.tp")

    def test_output_is_valid_base64url(self):
        """Output characters must only be URL-safe base64 alphabet."""
        from acme.dns_challenge import compute_dns_txt_value

        result = compute_dns_txt_value("some.keyauth")
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(c in valid_chars for c in result)


# ─── make_dns_provider ────────────────────────────────────────────────────────


class TestMakeDnsProvider:
    """Tests for acme.dns_challenge.make_dns_provider factory."""

    def test_dispatches_cloudflare(self):
        """make_dns_provider() returns CloudflareDnsProvider for cloudflare."""
        from acme.dns_challenge import CloudflareDnsProvider, make_dns_provider

        with patch("acme.dns_challenge.CloudflareDnsProvider.__init__", return_value=None) as mock_init:
            with patch("config.settings") as mock_settings:
                mock_settings.DNS_PROVIDER = "cloudflare"
                mock_settings.CLOUDFLARE_API_TOKEN = "token"
                mock_settings.CLOUDFLARE_ZONE_ID = "zone123"
                provider = make_dns_provider()
            mock_init.assert_called_once_with(api_token="token", zone_id="zone123")

    def test_dispatches_route53(self):
        """make_dns_provider() returns Route53DnsProvider for route53."""
        from acme.dns_challenge import Route53DnsProvider, make_dns_provider

        with patch("acme.dns_challenge.Route53DnsProvider.__init__", return_value=None) as mock_init:
            with patch("config.settings") as mock_settings:
                mock_settings.DNS_PROVIDER = "route53"
                mock_settings.AWS_ROUTE53_HOSTED_ZONE_ID = "Z123"
                mock_settings.AWS_REGION = "us-west-2"
                mock_settings.AWS_ACCESS_KEY_ID = ""
                mock_settings.AWS_SECRET_ACCESS_KEY = ""
                provider = make_dns_provider()
            mock_init.assert_called_once_with(
                hosted_zone_id="Z123",
                region="us-west-2",
                access_key_id="",
                secret_access_key="",
            )

    def test_dispatches_google(self):
        """make_dns_provider() returns GoogleCloudDnsProvider for google."""
        from acme.dns_challenge import GoogleCloudDnsProvider, make_dns_provider

        with patch("acme.dns_challenge.GoogleCloudDnsProvider.__init__", return_value=None) as mock_init:
            with patch("config.settings") as mock_settings:
                mock_settings.DNS_PROVIDER = "google"
                mock_settings.GOOGLE_PROJECT_ID = "my-project"
                mock_settings.GOOGLE_CLOUD_DNS_ZONE_NAME = "my-zone"
                mock_settings.GOOGLE_APPLICATION_CREDENTIALS = "/path/creds.json"
                provider = make_dns_provider()
            mock_init.assert_called_once_with(
                project_id="my-project",
                zone_name="my-zone",
                credentials_path="/path/creds.json",
            )

    def test_unknown_provider_raises(self):
        """make_dns_provider() raises ValueError for unknown providers."""
        from acme.dns_challenge import make_dns_provider

        with patch("config.settings") as mock_settings:
            mock_settings.DNS_PROVIDER = "unknown_provider"
            with pytest.raises(ValueError, match="Unknown DNS_PROVIDER"):
                make_dns_provider()

    def test_cloudflare_importerror_hint(self):
        """CloudflareDnsProvider raises ImportError with install hint if cloudflare not installed."""
        from acme.dns_challenge import CloudflareDnsProvider

        with patch.dict("sys.modules", {"cloudflare": None}):
            with pytest.raises(ImportError, match="uv sync --extra dns-cloudflare"):
                CloudflareDnsProvider(api_token="tok")

    def test_route53_importerror_hint(self):
        """Route53DnsProvider raises ImportError with install hint if boto3 not installed."""
        from acme.dns_challenge import Route53DnsProvider

        with patch.dict("sys.modules", {"boto3": None}):
            with pytest.raises(ImportError, match="uv sync --extra dns-route53"):
                Route53DnsProvider()

    def test_google_importerror_hint(self):
        """GoogleCloudDnsProvider raises ImportError with install hint if google-cloud-dns not installed."""
        from acme.dns_challenge import GoogleCloudDnsProvider

        with patch.dict("sys.modules", {"google.cloud": None, "google.cloud.dns": None}):
            with pytest.raises(ImportError, match="uv sync --extra dns-google"):
                GoogleCloudDnsProvider(project_id="p", zone_name="z")


# ─── CloudflareDnsProvider ────────────────────────────────────────────────────


class TestCloudflareDnsProvider:
    """Tests for CloudflareDnsProvider using a mocked cloudflare module."""

    @pytest.fixture
    def cf_mock(self):
        """Return a mock cloudflare module and Cloudflare client."""
        mock_cf_module = MagicMock()
        mock_client = MagicMock()
        mock_cf_module.Cloudflare.return_value = mock_client
        return mock_cf_module, mock_client

    def _make_provider(self, cf_mock, api_token="tok", zone_id="zone123"):
        from acme.dns_challenge import CloudflareDnsProvider

        cf_module, _ = cf_mock
        with patch.dict("sys.modules", {"cloudflare": cf_module}):
            # Re-import to pick up patched module
            provider = CloudflareDnsProvider.__new__(CloudflareDnsProvider)
            provider._cf_mod = cf_module
            provider._api_token = api_token
            provider._explicit_zone_id = zone_id
        return provider

    def test_create_txt_record_explicit_zone(self, cf_mock):
        """create_txt_record uses explicit zone_id without zone discovery."""
        cf_module, mock_client = cf_mock
        mock_client.dns.records.list.return_value = []  # No existing records

        provider = self._make_provider(cf_mock, zone_id="explicit-zone")
        provider.create_txt_record("api.example.com", "txt-value")

        mock_client.dns.records.create.assert_called_once_with(
            zone_id="explicit-zone",
            type="TXT",
            name="_acme-challenge.api.example.com",
            content="txt-value",
            ttl=60,
        )

    def test_create_txt_record_auto_discover_zone(self, cf_mock):
        """create_txt_record auto-discovers zone when zone_id is empty."""
        cf_module, mock_client = cf_mock

        mock_zone = MagicMock()
        mock_zone.id = "discovered-zone"
        mock_client.zones.list.return_value = [mock_zone]
        mock_client.dns.records.list.return_value = []

        provider = self._make_provider(cf_mock, zone_id="")
        provider.create_txt_record("api.example.com", "txt-value")

        # Zone discovery should have been called
        mock_client.zones.list.assert_called()
        mock_client.dns.records.create.assert_called_once()

    def test_create_txt_record_idempotent(self, cf_mock):
        """create_txt_record skips create if identical record already exists."""
        cf_module, mock_client = cf_mock

        existing = MagicMock()
        existing.content = "txt-value"
        mock_client.dns.records.list.return_value = [existing]

        provider = self._make_provider(cf_mock, zone_id="zone123")
        provider.create_txt_record("api.example.com", "txt-value")

        mock_client.dns.records.create.assert_not_called()

    def test_delete_txt_record_finds_and_deletes(self, cf_mock):
        """delete_txt_record finds the matching record and deletes it."""
        cf_module, mock_client = cf_mock

        record = MagicMock()
        record.id = "rec-abc"
        record.content = "txt-value"
        mock_client.dns.records.list.return_value = [record]

        provider = self._make_provider(cf_mock, zone_id="zone123")
        provider.delete_txt_record("api.example.com", "txt-value")

        mock_client.dns.records.delete.assert_called_once_with("rec-abc", zone_id="zone123")

    def test_delete_txt_record_swallows_errors(self, cf_mock):
        """delete_txt_record does not raise when an error occurs."""
        cf_module, mock_client = cf_mock
        mock_client.dns.records.list.side_effect = RuntimeError("API down")

        provider = self._make_provider(cf_mock, zone_id="zone123")
        # Must not raise
        provider.delete_txt_record("api.example.com", "txt-value")

    def test_delete_txt_record_missing_record_silent(self, cf_mock):
        """delete_txt_record silently does nothing if record not found."""
        cf_module, mock_client = cf_mock
        mock_client.dns.records.list.return_value = []

        provider = self._make_provider(cf_mock, zone_id="zone123")
        provider.delete_txt_record("api.example.com", "missing-value")

        mock_client.dns.records.delete.assert_not_called()


# ─── Route53DnsProvider ───────────────────────────────────────────────────────


class TestRoute53DnsProvider:
    """Tests for Route53DnsProvider using a mocked boto3 module."""

    @pytest.fixture
    def boto3_mock(self):
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        return mock_boto3, mock_client

    def _make_provider(self, boto3_mock, hosted_zone_id="Z123", region="us-east-1"):
        from acme.dns_challenge import Route53DnsProvider

        mock_boto3, _ = boto3_mock
        provider = Route53DnsProvider.__new__(Route53DnsProvider)
        provider._boto3 = mock_boto3
        provider._explicit_zone_id = hosted_zone_id
        provider._region = region
        provider._access_key_id = ""
        provider._secret_access_key = ""
        return provider

    def test_create_txt_record_upsert_with_quotes(self, boto3_mock):
        """create_txt_record wraps TXT value in double-quotes for Route53."""
        mock_boto3, mock_client = boto3_mock

        provider = self._make_provider(boto3_mock, hosted_zone_id="Z123")
        provider.create_txt_record("api.example.com", "txt-value")

        call_args = mock_client.change_resource_record_sets.call_args
        changes = call_args.kwargs["ChangeBatch"]["Changes"]
        assert len(changes) == 1
        assert changes[0]["Action"] == "UPSERT"
        resource_records = changes[0]["ResourceRecordSet"]["ResourceRecords"]
        assert resource_records == [{"Value": '"txt-value"'}]

    def test_create_txt_record_uses_explicit_zone_id(self, boto3_mock):
        """create_txt_record uses explicit hosted_zone_id."""
        mock_boto3, mock_client = boto3_mock

        provider = self._make_provider(boto3_mock, hosted_zone_id="EXPLICIT-ZONE")
        provider.create_txt_record("api.example.com", "txt")

        call_args = mock_client.change_resource_record_sets.call_args
        assert call_args.kwargs["HostedZoneId"] == "EXPLICIT-ZONE"

    def test_create_txt_record_auto_discover_zone(self, boto3_mock):
        """create_txt_record auto-discovers zone when hosted_zone_id is empty."""
        mock_boto3, mock_client = boto3_mock
        mock_client.list_hosted_zones_by_name.return_value = {
            "HostedZones": [{"Name": "example.com.", "Id": "/hostedzone/DISCOVERED"}]
        }

        provider = self._make_provider(boto3_mock, hosted_zone_id="")
        provider.create_txt_record("api.example.com", "txt")

        call_args = mock_client.change_resource_record_sets.call_args
        assert call_args.kwargs["HostedZoneId"] == "DISCOVERED"

    def test_delete_txt_record_uses_delete_action(self, boto3_mock):
        """delete_txt_record sends a DELETE change to Route53."""
        mock_boto3, mock_client = boto3_mock

        provider = self._make_provider(boto3_mock, hosted_zone_id="Z123")
        provider.delete_txt_record("api.example.com", "txt-value")

        call_args = mock_client.change_resource_record_sets.call_args
        changes = call_args.kwargs["ChangeBatch"]["Changes"]
        assert changes[0]["Action"] == "DELETE"

    def test_delete_txt_record_swallows_errors(self, boto3_mock):
        """delete_txt_record does not raise when Route53 returns an error."""
        mock_boto3, mock_client = boto3_mock
        mock_client.change_resource_record_sets.side_effect = RuntimeError("NoSuchChange")

        provider = self._make_provider(boto3_mock, hosted_zone_id="Z123")
        # Must not raise
        provider.delete_txt_record("api.example.com", "txt-value")


# ─── GoogleCloudDnsProvider ───────────────────────────────────────────────────


class TestGoogleCloudDnsProvider:
    """Tests for GoogleCloudDnsProvider using a mocked google.cloud.dns module."""

    @pytest.fixture
    def gcp_dns_mock(self):
        mock_dns_module = MagicMock()
        mock_gcp_client = MagicMock()
        mock_dns_module.Client.return_value = mock_gcp_client
        mock_zone = MagicMock()
        mock_gcp_client.zone.return_value = mock_zone
        return mock_dns_module, mock_gcp_client, mock_zone

    def _make_provider(self, gcp_dns_mock, project_id="my-project", zone_name="my-zone"):
        from acme.dns_challenge import GoogleCloudDnsProvider

        mock_dns_module, _, _ = gcp_dns_mock
        provider = GoogleCloudDnsProvider.__new__(GoogleCloudDnsProvider)
        provider._gcp_dns = mock_dns_module
        provider._project_id = project_id
        provider._zone_name = zone_name
        provider._credentials_path = ""
        return provider

    def test_create_txt_record_calls_add_and_create(self, gcp_dns_mock):
        """create_txt_record calls add_record_set() and changes.create()."""
        mock_dns_module, mock_gcp_client, mock_zone = gcp_dns_mock

        provider = self._make_provider(gcp_dns_mock)
        provider.create_txt_record("api.example.com", "txt-value")

        mock_zone.resource_record_set.assert_called_once_with(
            "_acme-challenge.api.example.com.", "TXT", 60, ['"txt-value"']
        )
        mock_zone.changes.return_value.add_record_set.assert_called_once()
        mock_zone.changes.return_value.create.assert_called_once()

    def test_delete_txt_record_calls_delete_and_create(self, gcp_dns_mock):
        """delete_txt_record calls delete_record_set() and changes.create()."""
        mock_dns_module, mock_gcp_client, mock_zone = gcp_dns_mock

        provider = self._make_provider(gcp_dns_mock)
        provider.delete_txt_record("api.example.com", "txt-value")

        mock_zone.changes.return_value.delete_record_set.assert_called_once()
        mock_zone.changes.return_value.create.assert_called_once()

    def test_delete_txt_record_swallows_errors(self, gcp_dns_mock):
        """delete_txt_record does not raise on errors."""
        mock_dns_module, mock_gcp_client, mock_zone = gcp_dns_mock
        mock_zone.changes.return_value.create.side_effect = RuntimeError("API error")

        provider = self._make_provider(gcp_dns_mock)
        # Must not raise
        provider.delete_txt_record("api.example.com", "txt-value")


# ─── order_initializer (DNS-01) ───────────────────────────────────────────────


class TestOrderInitializerDns01:
    """Tests for order_initializer node when HTTP_CHALLENGE_MODE='dns'."""

    def _make_state(self, domain="api.example.com"):
        return {
            "current_domain": domain,
            "acme_account_url": "https://acme.test/acct/1",
            "account_key_path": "/tmp/account.key",
            "current_nonce": "nonce123",
            "error_log": [],
        }

    def _make_authz(self, domain, token="tok123"):
        return {
            "identifier": {"type": "dns", "value": domain},
            "status": "pending",
            "challenges": [
                {"type": "dns-01", "url": "https://acme.test/ch/dns/1", "token": token},
                {"type": "http-01", "url": "https://acme.test/ch/http/1", "token": token},
            ],
        }

    def test_dns01_challenge_selected(self):
        """order_initializer selects dns-01 challenge when mode='dns'."""
        from agent.nodes.order import order_initializer

        state = self._make_state()
        authz = self._make_authz("api.example.com", token="mytoken")
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        mock_account_key = MagicMock()

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=mock_account_key), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="thumbprint"), \
             patch("agent.nodes.order.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "dns"

            result = order_initializer(state)

        assert "current_order" in result
        order = result["current_order"]
        assert order["challenge_urls"] == ["https://acme.test/ch/dns/1"]

    def test_dns01_populates_auth_domains(self):
        """order_initializer populates auth_domains from authz identifier."""
        from agent.nodes.order import order_initializer

        state = self._make_state()
        authz = self._make_authz("api.example.com")
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=MagicMock()), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="tp"), \
             patch("agent.nodes.order.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "dns"

            result = order_initializer(state)

        order = result["current_order"]
        assert order["auth_domains"] == ["api.example.com"]

    def test_dns01_populates_dns_txt_values(self):
        """order_initializer populates dns_txt_values with correct SHA-256 values."""
        from acme.dns_challenge import compute_dns_txt_value
        from agent.nodes.order import order_initializer

        state = self._make_state()
        authz = self._make_authz("api.example.com", token="tok")
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=MagicMock()), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="tp"), \
             patch("agent.nodes.order.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "dns"

            result = order_initializer(state)

        order = result["current_order"]
        expected_txt = compute_dns_txt_value("tok.tp")
        assert order["dns_txt_values"] == [expected_txt]

    def test_http01_dns_txt_values_empty(self):
        """order_initializer leaves dns_txt_values empty for HTTP-01 mode."""
        from agent.nodes.order import order_initializer

        state = self._make_state()
        authz = self._make_authz("api.example.com")
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=MagicMock()), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="tp"), \
             patch("agent.nodes.order.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "standalone"

            result = order_initializer(state)

        order = result["current_order"]
        assert order["dns_txt_values"] == []

    def test_missing_dns01_challenge_returns_error(self):
        """order_initializer returns error_log entry when dns-01 challenge not found."""
        from agent.nodes.order import order_initializer

        state = self._make_state()
        # Authz with only http-01, no dns-01
        authz = {
            "identifier": {"type": "dns", "value": "api.example.com"},
            "status": "pending",
            "challenges": [
                {"type": "http-01", "url": "https://acme.test/ch/http/1", "token": "tok"}
            ],
        }
        order_body = {
            "status": "pending",
            "authorizations": ["https://acme.test/authz/1"],
            "finalize": "https://acme.test/finalize/1",
        }

        mock_client = MagicMock()
        mock_client.get_directory.return_value = {}
        mock_client.create_order.return_value = (order_body, "https://acme.test/order/1", "nonce2")
        mock_client.get_authorization.return_value = authz

        with patch("agent.nodes.order.make_client", return_value=mock_client), \
             patch("agent.nodes.order.jwslib.load_account_key", return_value=MagicMock()), \
             patch("agent.nodes.order.jwslib.compute_jwk_thumbprint", return_value="tp"), \
             patch("agent.nodes.order.settings") as mock_settings:

            mock_settings.HTTP_CHALLENGE_MODE = "dns"

            result = order_initializer(state)

        assert "error_log" in result
        assert any("dns-01" in e for e in result["error_log"])


# ─── challenge_setup (DNS branch) ─────────────────────────────────────────────


class TestChallengeSetupDns:
    """Tests for challenge_setup when mode='dns'."""

    def _make_order(self, domains=None, txt_values=None):
        domains = domains or ["api.example.com"]
        txt_values = txt_values or ["txtval1"]
        return {
            "challenge_tokens": ["tok1"],
            "key_authorizations": ["tok1.tp"],
            "auth_domains": domains,
            "dns_txt_values": txt_values,
        }

    def _make_state(self, order):
        return {
            "current_order": order,
            "error_log": [],
        }

    def test_create_txt_record_called_for_each_domain(self):
        """challenge_setup calls create_txt_record once per domain."""
        from agent.nodes.challenge import challenge_setup

        order = self._make_order(
            domains=["a.example.com", "b.example.com"],
            txt_values=["val1", "val2"],
        )
        state = self._make_state(order)
        mock_provider = MagicMock()

        with patch("agent.nodes.challenge.settings") as mock_settings, \
             patch("agent.nodes.challenge.make_dns_provider", return_value=mock_provider):
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            mock_settings.DNS_PROPAGATION_WAIT_SECONDS = 0

            challenge_setup(state)

        assert mock_provider.create_txt_record.call_count == 2
        mock_provider.create_txt_record.assert_any_call("a.example.com", "val1")
        mock_provider.create_txt_record.assert_any_call("b.example.com", "val2")

    def test_propagation_sleep_called_when_positive(self):
        """challenge_setup sleeps for DNS_PROPAGATION_WAIT_SECONDS when > 0."""
        from agent.nodes.challenge import challenge_setup

        order = self._make_order()
        state = self._make_state(order)
        mock_provider = MagicMock()

        with patch("agent.nodes.challenge.settings") as mock_settings, \
             patch("agent.nodes.challenge.make_dns_provider", return_value=mock_provider), \
             patch("agent.nodes.challenge.time.sleep") as mock_sleep:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            mock_settings.DNS_PROPAGATION_WAIT_SECONDS = 30

            challenge_setup(state)

        mock_sleep.assert_called_once_with(30)

    def test_propagation_sleep_skipped_when_zero(self):
        """challenge_setup skips sleep when DNS_PROPAGATION_WAIT_SECONDS=0."""
        from agent.nodes.challenge import challenge_setup

        order = self._make_order()
        state = self._make_state(order)
        mock_provider = MagicMock()

        with patch("agent.nodes.challenge.settings") as mock_settings, \
             patch("agent.nodes.challenge.make_dns_provider", return_value=mock_provider), \
             patch("agent.nodes.challenge.time.sleep") as mock_sleep:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            mock_settings.DNS_PROPAGATION_WAIT_SECONDS = 0

            challenge_setup(state)

        mock_sleep.assert_not_called()

    def test_returns_empty_dict(self):
        """challenge_setup returns empty dict on success (no state update)."""
        from agent.nodes.challenge import challenge_setup

        order = self._make_order()
        state = self._make_state(order)
        mock_provider = MagicMock()

        with patch("agent.nodes.challenge.settings") as mock_settings, \
             patch("agent.nodes.challenge.make_dns_provider", return_value=mock_provider):
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            mock_settings.DNS_PROPAGATION_WAIT_SECONDS = 0

            result = challenge_setup(state)

        assert result == {}


# ─── _cleanup_challenge (DNS branch) ─────────────────────────────────────────


class TestCleanupChallengeDns:
    """Tests for _cleanup_challenge when mode='dns'."""

    def _make_order(self, domains=None, txt_values=None):
        return {
            "challenge_tokens": ["tok1"],
            "key_authorizations": ["tok1.tp"],
            "auth_domains": domains or ["api.example.com"],
            "dns_txt_values": txt_values or ["val1"],
        }

    def test_delete_called_for_each_domain(self):
        """_cleanup_challenge calls delete_txt_record for each domain."""
        import agent.nodes.challenge as challenge_mod
        from agent.nodes.challenge import _cleanup_challenge

        order = self._make_order(
            domains=["a.example.com", "b.example.com"],
            txt_values=["val1", "val2"],
        )
        state = {"current_order": order}
        mock_provider = MagicMock()
        challenge_mod._dns_provider = mock_provider

        with patch("agent.nodes.challenge.settings") as mock_settings:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            _cleanup_challenge(state)

        assert mock_provider.delete_txt_record.call_count == 2
        mock_provider.delete_txt_record.assert_any_call("a.example.com", "val1")
        mock_provider.delete_txt_record.assert_any_call("b.example.com", "val2")

        # Provider should be cleared
        assert challenge_mod._dns_provider is None

    def test_continues_on_partial_failure(self):
        """_cleanup_challenge continues deleting even when one domain fails."""
        import agent.nodes.challenge as challenge_mod
        from agent.nodes.challenge import _cleanup_challenge

        order = self._make_order(
            domains=["a.example.com", "b.example.com"],
            txt_values=["val1", "val2"],
        )
        state = {"current_order": order}
        mock_provider = MagicMock()
        # First call raises, second should still proceed
        mock_provider.delete_txt_record.side_effect = [RuntimeError("API down"), None]
        challenge_mod._dns_provider = mock_provider

        with patch("agent.nodes.challenge.settings") as mock_settings:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            # Must not raise
            _cleanup_challenge(state)

        assert mock_provider.delete_txt_record.call_count == 2

    def test_safe_when_no_provider(self):
        """_cleanup_challenge is safe when _dns_provider is None."""
        import agent.nodes.challenge as challenge_mod
        from agent.nodes.challenge import _cleanup_challenge

        challenge_mod._dns_provider = None
        state = {"current_order": self._make_order()}

        with patch("agent.nodes.challenge.settings") as mock_settings:
            mock_settings.HTTP_CHALLENGE_MODE = "dns"
            # Must not raise
            _cleanup_challenge(state)


# ─── Config validation ────────────────────────────────────────────────────────


class TestConfigValidation:
    """Tests for config.py DNS-related validators."""

    def test_dns_mode_accepted(self):
        """HTTP_CHALLENGE_MODE='dns' passes validation."""
        from pydantic import ValidationError

        from config import Settings

        # Build a Settings object with dns mode — should not raise
        s = Settings(
            HTTP_CHALLENGE_MODE="dns",
            DNS_PROVIDER="cloudflare",
            CLOUDFLARE_API_TOKEN="tok",
            # Suppress unrelated validators
            CA_PROVIDER="letsencrypt",
            MANAGED_DOMAINS="example.com",
        )
        assert s.HTTP_CHALLENGE_MODE == "dns"

    def test_invalid_mode_rejected(self):
        """HTTP_CHALLENGE_MODE='ftp' is rejected."""
        from pydantic import ValidationError

        from config import Settings

        with pytest.raises((ValidationError, ValueError)):
            Settings(
                HTTP_CHALLENGE_MODE="ftp",
                CA_PROVIDER="letsencrypt",
            )

    def test_cloudflare_missing_token_raises(self):
        """DNS mode with cloudflare provider and no token raises ValueError."""
        from pydantic import ValidationError

        from config import Settings

        with pytest.raises((ValidationError, ValueError)):
            Settings(
                HTTP_CHALLENGE_MODE="dns",
                DNS_PROVIDER="cloudflare",
                CLOUDFLARE_API_TOKEN="",  # Missing!
                CA_PROVIDER="letsencrypt",
                MANAGED_DOMAINS="example.com",
            )

    def test_google_missing_project_id_raises(self):
        """DNS mode with google provider and no project_id raises ValueError."""
        from pydantic import ValidationError

        from config import Settings

        with pytest.raises((ValidationError, ValueError)):
            Settings(
                HTTP_CHALLENGE_MODE="dns",
                DNS_PROVIDER="google",
                GOOGLE_PROJECT_ID="",  # Missing!
                CA_PROVIDER="letsencrypt",
                MANAGED_DOMAINS="example.com",
            )

    def test_route53_no_mandatory_fields(self):
        """Route53 uses credential chain — no mandatory fields required."""
        from config import Settings

        s = Settings(
            HTTP_CHALLENGE_MODE="dns",
            DNS_PROVIDER="route53",
            # No AWS keys — uses credential chain / instance role
            CA_PROVIDER="letsencrypt",
            MANAGED_DOMAINS="example.com",
        )
        assert s.DNS_PROVIDER == "route53"

    def test_standalone_mode_unchanged(self):
        """standalone mode validation is unaffected by DNS changes."""
        from config import Settings

        s = Settings(
            HTTP_CHALLENGE_MODE="standalone",
            CA_PROVIDER="letsencrypt",
            MANAGED_DOMAINS="example.com",
        )
        assert s.HTTP_CHALLENGE_MODE == "standalone"

    def test_webroot_mode_unchanged(self):
        """webroot mode still requires WEBROOT_PATH."""
        from pydantic import ValidationError

        from config import Settings

        with pytest.raises((ValidationError, ValueError), match="WEBROOT_PATH"):
            Settings(
                HTTP_CHALLENGE_MODE="webroot",
                WEBROOT_PATH="",
                CA_PROVIDER="letsencrypt",
                MANAGED_DOMAINS="example.com",
            )
