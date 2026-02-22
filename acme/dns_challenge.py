"""
DNS-01 challenge support for the ACME certificate lifecycle agent.

Provides:
  compute_dns_txt_value(key_authorization) -> str
      Computes the TXT record value: base64url(SHA-256(key_authorization))

  DnsProvider (ABC)
      Interface that all DNS provider implementations must satisfy.

  CloudflareDnsProvider — uses the `cloudflare` library (>=3.0)
  Route53DnsProvider    — uses `boto3`
  GoogleCloudDnsProvider — uses `google-cloud-dns`

  make_dns_provider() -> DnsProvider
      Factory that reads settings and returns the appropriate provider.

DNS-01 protocol (RFC 8555 §8.4):
  1. Compute key_authorization = token + "." + jwk_thumbprint  (same as HTTP-01)
  2. TXT record value = base64url(SHA-256(key_authorization))
  3. DNS name = _acme-challenge.{domain}
  4. Create record → wait for propagation → POST challenge URL → poll
"""
from __future__ import annotations

import base64
import hashlib
import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


# ─── TXT value computation ─────────────────────────────────────────────────────


def compute_dns_txt_value(key_authorization: str) -> str:
    """Return base64url(SHA-256(key_authorization)) with no padding.

    This is the value to place in the _acme-challenge.<domain> TXT record
    as specified by RFC 8555 §8.4.
    """
    digest = hashlib.sha256(key_authorization.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ─── Provider ABC ─────────────────────────────────────────────────────────────


class DnsProvider(ABC):
    """Abstract base for DNS-01 TXT record management."""

    @abstractmethod
    def create_txt_record(self, domain: str, txt_value: str) -> None:
        """Create (or update) _acme-challenge.<domain> TXT record.

        Must be idempotent — if the record already exists with the same value,
        do nothing.
        """

    @abstractmethod
    def delete_txt_record(self, domain: str, txt_value: str) -> None:
        """Delete _acme-challenge.<domain> TXT record with the given value.

        Best-effort — if the record does not exist, swallow the error silently.
        """

    @staticmethod
    def _acme_record_name(domain: str) -> str:
        """Return the full _acme-challenge DNS name for a domain."""
        return f"_acme-challenge.{domain}"


# ─── Cloudflare ───────────────────────────────────────────────────────────────


class CloudflareDnsProvider(DnsProvider):
    """DNS-01 provider backed by the Cloudflare API (cloudflare>=3.0)."""

    def __init__(self, api_token: str, zone_id: str = "") -> None:
        try:
            import cloudflare as cf_mod  # noqa: F401 — verify importable
            self._cf_mod = cf_mod
        except ImportError as exc:
            raise ImportError(
                "cloudflare package is required for DNS_PROVIDER='cloudflare'. "
                "Install it with: uv sync --extra dns-cloudflare"
            ) from exc

        self._api_token = api_token
        self._explicit_zone_id = zone_id

    def _get_client(self):
        return self._cf_mod.Cloudflare(api_token=self._api_token)

    def _resolve_zone_id(self, domain: str) -> str:
        """Return zone ID — uses explicit value if set, else auto-discovers."""
        if self._explicit_zone_id:
            return self._explicit_zone_id

        cf = self._get_client()
        # Walk from most-specific to least-specific label group
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            zones = cf.zones.list(name=candidate)
            zone_list = list(zones)
            if zone_list:
                return zone_list[0].id

        raise ValueError(f"Could not discover Cloudflare zone for domain: {domain}")

    def create_txt_record(self, domain: str, txt_value: str) -> None:
        cf = self._get_client()
        zone_id = self._resolve_zone_id(domain)
        name = self._acme_record_name(domain)

        # Idempotent: skip if an identical record already exists
        existing = list(cf.dns.records.list(zone_id=zone_id, name=name, type="TXT"))
        for record in existing:
            if getattr(record, "content", None) == txt_value:
                logger.debug("TXT record %s already exists — skipping create", name)
                return

        cf.dns.records.create(
            zone_id=zone_id,
            type="TXT",
            name=name,
            content=txt_value,
            ttl=60,
        )
        logger.info("Created Cloudflare TXT record %s", name)

    def delete_txt_record(self, domain: str, txt_value: str) -> None:
        try:
            cf = self._get_client()
            zone_id = self._resolve_zone_id(domain)
            name = self._acme_record_name(domain)

            records = list(cf.dns.records.list(zone_id=zone_id, name=name, type="TXT"))
            for record in records:
                if getattr(record, "content", None) == txt_value:
                    cf.dns.records.delete(record.id, zone_id=zone_id)
                    logger.info("Deleted Cloudflare TXT record %s", name)
                    return
            logger.debug("TXT record %s not found — nothing to delete", name)
        except Exception as exc:
            logger.warning("Failed to delete Cloudflare TXT record for %s: %s", domain, exc)


# ─── Route 53 ─────────────────────────────────────────────────────────────────


class Route53DnsProvider(DnsProvider):
    """DNS-01 provider backed by AWS Route 53 (boto3)."""

    def __init__(
        self,
        hosted_zone_id: str = "",
        region: str = "us-east-1",
        access_key_id: str = "",
        secret_access_key: str = "",
    ) -> None:
        try:
            import boto3  # noqa: F401 — verify importable
            self._boto3 = boto3
        except ImportError as exc:
            raise ImportError(
                "boto3 package is required for DNS_PROVIDER='route53'. "
                "Install it with: uv sync --extra dns-route53"
            ) from exc

        self._explicit_zone_id = hosted_zone_id
        self._region = region
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key

    def _get_client(self):
        kwargs: dict = {"region_name": self._region}
        if self._access_key_id:
            kwargs["aws_access_key_id"] = self._access_key_id
        if self._secret_access_key:
            kwargs["aws_secret_access_key"] = self._secret_access_key
        return self._boto3.client("route53", **kwargs)

    def _resolve_zone_id(self, domain: str) -> str:
        if self._explicit_zone_id:
            return self._explicit_zone_id

        client = self._get_client()
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:]) + "."
            response = client.list_hosted_zones_by_name(DNSName=candidate, MaxItems="1")
            zones = response.get("HostedZones", [])
            if zones and zones[0]["Name"] == candidate:
                # Extract bare ID from "/hostedzone/ZXXXXX"
                return zones[0]["Id"].split("/")[-1]

        raise ValueError(f"Could not discover Route53 hosted zone for domain: {domain}")

    def _txt_value(self, txt: str) -> str:
        """Route53 requires TXT record values wrapped in double-quotes."""
        return f'"{txt}"'

    def create_txt_record(self, domain: str, txt_value: str) -> None:
        client = self._get_client()
        zone_id = self._resolve_zone_id(domain)
        name = self._acme_record_name(domain) + "."

        client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": name,
                            "Type": "TXT",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": self._txt_value(txt_value)}],
                        },
                    }
                ]
            },
        )
        logger.info("Created/updated Route53 TXT record %s", name)

    def delete_txt_record(self, domain: str, txt_value: str) -> None:
        try:
            client = self._get_client()
            zone_id = self._resolve_zone_id(domain)
            name = self._acme_record_name(domain) + "."

            client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": "DELETE",
                            "ResourceRecordSet": {
                                "Name": name,
                                "Type": "TXT",
                                "TTL": 60,
                                "ResourceRecords": [{"Value": self._txt_value(txt_value)}],
                            },
                        }
                    ]
                },
            )
            logger.info("Deleted Route53 TXT record %s", name)
        except Exception as exc:
            logger.warning("Failed to delete Route53 TXT record for %s: %s", domain, exc)


# ─── Google Cloud DNS ─────────────────────────────────────────────────────────


class GoogleCloudDnsProvider(DnsProvider):
    """DNS-01 provider backed by Google Cloud DNS (google-cloud-dns>=3.0)."""

    def __init__(
        self,
        project_id: str,
        zone_name: str,
        credentials_path: str = "",
    ) -> None:
        try:
            from google.cloud import dns as gcp_dns  # noqa: F401
            self._gcp_dns = gcp_dns
        except ImportError as exc:
            raise ImportError(
                "google-cloud-dns package is required for DNS_PROVIDER='google'. "
                "Install it with: uv sync --extra dns-google"
            ) from exc

        self._project_id = project_id
        self._zone_name = zone_name
        self._credentials_path = credentials_path

    def _get_client(self):
        import os
        if self._credentials_path:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self._credentials_path
        return self._gcp_dns.Client(project=self._project_id)

    def create_txt_record(self, domain: str, txt_value: str) -> None:
        client = self._get_client()
        zone = client.zone(self._zone_name)
        name = self._acme_record_name(domain) + "."

        # Check if TXT record already exists
        expected_rdata = [f'"{txt_value}"']
        existing_txt_record = None
        for record in zone.list_resource_record_sets():
            if record.name == name and record.record_type == "TXT":
                existing_txt_record = record
                break

        # Idempotent: if identical record exists, skip
        if existing_txt_record:
            if existing_txt_record.rdata == expected_rdata:
                logger.debug("TXT record %s already exists with correct value — skipping create", name)
                return
            # Record exists with different value, delete it first
            changes = zone.changes()
            changes.delete_record_set(existing_txt_record)
            changes.create()
            logger.debug("Deleted existing TXT record %s with different value", name)

        # Create the record
        record_set = zone.resource_record_set(name, "TXT", 60, expected_rdata)
        changes = zone.changes()
        changes.add_record_set(record_set)
        changes.create()
        logger.info("Created Google Cloud DNS TXT record %s", name)

    def delete_txt_record(self, domain: str, txt_value: str) -> None:
        try:
            client = self._get_client()
            zone = client.zone(self._zone_name)
            name = self._acme_record_name(domain) + "."

            record_set = zone.resource_record_set(name, "TXT", 60, [f'"{txt_value}"'])
            changes = zone.changes()
            changes.delete_record_set(record_set)
            changes.create()
            logger.info("Deleted Google Cloud DNS TXT record %s", name)
        except Exception as exc:
            logger.warning(
                "Failed to delete Google Cloud DNS TXT record for %s: %s", domain, exc
            )


# ─── Factory ──────────────────────────────────────────────────────────────────


def make_dns_provider() -> DnsProvider:
    """Instantiate and return the configured DNS provider.

    Reads settings at call time (mirrors make_client() pattern).
    Raises ValueError for unknown DNS_PROVIDER values.
    """
    from config import settings  # late import to avoid circular dependency

    provider = settings.DNS_PROVIDER

    if provider == "cloudflare":
        return CloudflareDnsProvider(
            api_token=settings.CLOUDFLARE_API_TOKEN,
            zone_id=settings.CLOUDFLARE_ZONE_ID,
        )
    elif provider == "route53":
        return Route53DnsProvider(
            hosted_zone_id=settings.AWS_ROUTE53_HOSTED_ZONE_ID,
            region=settings.AWS_REGION,
            access_key_id=settings.AWS_ACCESS_KEY_ID,
            secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )
    elif provider == "google":
        return GoogleCloudDnsProvider(
            project_id=settings.GOOGLE_PROJECT_ID,
            zone_name=settings.GOOGLE_CLOUD_DNS_ZONE_NAME,
            credentials_path=settings.GOOGLE_APPLICATION_CREDENTIALS,
        )
    else:
        raise ValueError(
            f"Unknown DNS_PROVIDER: {provider!r}. "
            "Must be one of: cloudflare, route53, google"
        )
