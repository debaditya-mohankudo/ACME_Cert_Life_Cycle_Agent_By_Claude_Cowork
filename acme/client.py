"""
Low-level ACME RFC 8555 HTTP client.

This client is intentionally **stateless**: all account/nonce state is passed
in by the caller (the LangGraph nodes), making it easy to test with mock HTTP.

RFC 8555 compliance notes
--------------------------
* POST-as-GET: authorizations must be fetched with a signed empty payload, not
  plain GET.  Pass `account_key` and `account_url` to `get_authorization` /
  `poll_authorization` to enable this.
* badNonce retry: ACME servers (including Pebble, which rejects 5 % of nonces
  intentionally) return a fresh `Replay-Nonce` header even on error responses.
  `_post_signed` automatically retries up to `_NONCE_RETRIES` times.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from josepy.jwk import JWKRSA
import requests

from acme import jws as jwslib

_NONCE_RETRIES = 3


class AcmeError(Exception):
    """Raised when the ACME server returns an error response."""

    def __init__(self, status_code: int, body: dict, new_nonce: str = "") -> None:
        self.status_code = status_code
        self.body = body
        self.new_nonce = new_nonce
        problem_type = body.get("type", "unknown")
        detail = body.get("detail", str(body))
        super().__init__(f"ACME {status_code}: {problem_type} — {detail}")


class DigiCertAcmeClient:
    """
    Implements the RFC 8555 ACME protocol against DigiCert's endpoint.
    Also tested against Pebble (local stub) and Let's Encrypt staging.
    """

    def __init__(
        self,
        directory_url: str,
        eab_key_id: str = "",
        eab_hmac_key: str = "",
        timeout: int = 30,
        ca_bundle: str = "",
        insecure: bool = False,
    ) -> None:
        self.directory_url = directory_url
        self.eab_key_id = eab_key_id
        self.eab_hmac_key = eab_hmac_key
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "acme-cert-agent/1.0"})

        if insecure:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self._session.verify = False
        elif ca_bundle:
            self._session.verify = ca_bundle

    # ── Directory & nonce ─────────────────────────────────────────────────

    def get_directory(self) -> dict:
        """GET /directory — discover ACME endpoint URLs."""
        resp = self._session.get(self.directory_url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def get_nonce(self, directory: dict) -> str:
        """HEAD /newNonce — fetch a fresh anti-replay nonce."""
        resp = self._session.head(directory["newNonce"], timeout=self.timeout)
        nonce = resp.headers.get("Replay-Nonce")
        if not nonce:
            raise AcmeError(resp.status_code, {"detail": "No Replay-Nonce header"})
        return nonce

    # ── Account ───────────────────────────────────────────────────────────

    def create_account(
        self,
        account_key: JWKRSA,
        eab_key_id: str,
        eab_hmac_key: str,
        nonce: str,
        directory: dict,
    ) -> tuple[str, str]:
        """
        POST /newAccount, with EAB binding when credentials are provided.
        DigiCert requires EAB; Pebble and Let's Encrypt staging do not.
        Returns (account_url, new_nonce).
        """
        new_account_url = directory["newAccount"]
        payload: dict = {"termsOfServiceAgreed": True}

        if eab_key_id and eab_hmac_key:
            payload["externalAccountBinding"] = jwslib.create_eab_jws(
                account_key, eab_key_id, eab_hmac_key, new_account_url
            )

        resp = self._post_signed(payload, account_key, nonce, new_account_url, directory=directory)
        return resp.headers.get("Location", ""), resp.headers.get("Replay-Nonce", "")

    def lookup_account(
        self,
        account_key: JWKRSA,
        nonce: str,
        directory: dict,
    ) -> tuple[Optional[str], str]:
        """
        POST /newAccount with onlyReturnExisting=True.
        Returns (account_url or None, new_nonce).
        """
        new_account_url = directory["newAccount"]
        try:
            resp = self._post_signed(
                {"onlyReturnExisting": True}, account_key, nonce, new_account_url, directory=directory
            )
            return resp.headers.get("Location"), resp.headers.get("Replay-Nonce", "")
        except AcmeError as e:
            if e.status_code == 400:
                return None, e.new_nonce
            raise

    # ── Orders ────────────────────────────────────────────────────────────

    def create_order(
        self,
        domains: list[str],
        account_key: JWKRSA,
        account_url: str,
        nonce: str,
        directory: dict,
    ) -> tuple[dict, str, str]:
        """
        POST /newOrder — create a certificate order for one or more domains.
        Returns (order_body, order_url, new_nonce).
        """
        new_order_url = directory["newOrder"]
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        resp = self._post_signed(payload, account_key, nonce, new_order_url, account_url, directory=directory)
        return resp.json(), resp.headers.get("Location", ""), resp.headers.get("Replay-Nonce", "")

    def get_order(
        self,
        order_url: str,
        account_key: JWKRSA | None = None,
        account_url: str | None = None,
    ) -> dict:
        """
        Fetch an order object.
        Uses POST-as-GET when account credentials are provided (required by Pebble).
        """
        if account_key and account_url:
            directory = self.get_directory()
            nonce = self.get_nonce(directory)
            resp = self._post_signed(None, account_key, nonce, order_url, account_url, directory=directory)
        else:
            resp = self._session.get(order_url, timeout=self.timeout)
            resp.raise_for_status()
        return resp.json()

    # ── Authorizations & challenges ───────────────────────────────────────

    def get_authorization(
        self,
        auth_url: str,
        account_key: JWKRSA | None = None,
        account_url: str | None = None,
    ) -> dict:
        """
        Fetch an authorization object.

        Uses POST-as-GET (RFC 8555 §7.4.1) when `account_key` and `account_url`
        are provided — required by Pebble and modern ACME servers.
        Falls back to plain GET for backward compatibility when they are omitted.
        """
        if account_key and account_url:
            # Fetch a fresh nonce internally so the caller doesn't have to
            # thread it through every poll iteration.
            directory = self.get_directory()
            nonce = self.get_nonce(directory)
            resp = self._post_signed(None, account_key, nonce, auth_url, account_url, directory=directory)
        else:
            resp = self._session.get(auth_url, timeout=self.timeout)
            resp.raise_for_status()
        return resp.json()

    def respond_to_challenge(
        self,
        challenge_url: str,
        account_key: JWKRSA,
        account_url: str,
        nonce: str,
    ) -> tuple[dict, str]:
        """
        POST challenge URL with empty payload {} to tell the CA to verify.
        Returns (challenge_body, new_nonce).
        """
        resp = self._post_signed({}, account_key, nonce, challenge_url, account_url)
        return resp.json(), resp.headers.get("Replay-Nonce", "")

    def poll_authorization(
        self,
        auth_url: str,
        account_key: JWKRSA | None = None,
        account_url: str | None = None,
        max_attempts: int = 10,
        poll_interval: float = 2.0,
    ) -> str:
        """
        Poll an authorization URL until status is 'valid' or 'invalid'.

        Pass `account_key` and `account_url` to use POST-as-GET (required by
        Pebble and RFC 8555-compliant servers).
        Returns the final status string ('valid').
        Raises AcmeError on timeout or 'invalid'.
        """
        for _ in range(max_attempts):
            authz = self.get_authorization(auth_url, account_key, account_url)
            status = authz.get("status", "pending")
            if status == "valid":
                return status
            if status == "invalid":
                raise AcmeError(
                    200,
                    {
                        "type": "urn:ietf:params:acme:error:unauthorized",
                        "detail": f"Authorization invalid: {authz}",
                    },
                )
            time.sleep(poll_interval)

        raise AcmeError(
            0,
            {
                "type": "timeout",
                "detail": f"Authorization did not become valid after {max_attempts} polls",
            },
        )

    # ── Finalization & certificate download ───────────────────────────────

    def finalize_order(
        self,
        finalize_url: str,
        csr_der: bytes,
        account_key: JWKRSA,
        account_url: str,
        nonce: str,
    ) -> tuple[dict, str]:
        """
        POST /finalize — submit DER-encoded CSR.
        Returns (finalize_response_body, new_nonce).
        """
        import base64
        csr_b64 = base64.urlsafe_b64encode(csr_der).rstrip(b"=").decode()
        resp = self._post_signed({"csr": csr_b64}, account_key, nonce, finalize_url, account_url)
        return resp.json(), resp.headers.get("Replay-Nonce", "")

    def poll_order_for_certificate(
        self,
        order_url: str,
        account_key: JWKRSA | None = None,
        account_url: str | None = None,
        max_attempts: int = 20,
        poll_interval: float = 3.0,
    ) -> str:
        """
        Poll order until status is 'valid' (certificate ready).
        Pass account credentials to use POST-as-GET (required by Pebble).
        Returns the certificate URL.
        """
        for _ in range(max_attempts):
            order = self.get_order(order_url, account_key, account_url)
            status = order.get("status")
            if status == "valid":
                cert_url = order.get("certificate")
                if not cert_url:
                    raise AcmeError(0, {"detail": "Order valid but no certificate URL"})
                return cert_url
            if status == "invalid":
                raise AcmeError(
                    0,
                    {"type": "invalid", "detail": f"Order became invalid: {order}"},
                )
            time.sleep(poll_interval)

        raise AcmeError(
            0,
            {"type": "timeout", "detail": "Order did not become valid (certificate not issued)"},
        )

    def download_certificate(
        self,
        cert_url: str,
        account_key: JWKRSA,
        account_url: str,
        nonce: str,
    ) -> tuple[str, str]:
        """
        POST-as-GET the certificate URL and return (full_chain_pem, new_nonce).
        The PEM chain from DigiCert is: leaf cert + intermediates.
        """
        resp = self._post_signed(
            None, account_key, nonce, cert_url, account_url,
            accept="application/pem-certificate-chain",
        )
        return resp.text, resp.headers.get("Replay-Nonce", "")

    # ── Internal ──────────────────────────────────────────────────────────

    def _post_signed(
        self,
        payload: dict | None,
        account_key: JWKRSA,
        nonce: str,
        url: str,
        account_url: str | None = None,
        accept: str = "application/json",
        directory: dict | None = None,
    ) -> requests.Response:
        """
        Sign *payload* with *account_key* and POST to *url*, retrying up to
        `_NONCE_RETRIES` times on `badNonce` responses.

        ACME servers return a fresh `Replay-Nonce` even in error responses, so
        we extract it and re-sign rather than fetching a new nonce (saves one
        round-trip per retry).
        """
        current_nonce = nonce
        for attempt in range(_NONCE_RETRIES):
            body = jwslib.sign_request(payload, account_key, current_nonce, url, account_url)
            resp = self._session.post(
                url,
                json=body,
                headers={
                    "Content-Type": "application/jose+json",
                    "Accept": accept,
                },
                timeout=self.timeout,
            )
            if resp.ok:
                return resp

            try:
                error_body = resp.json()
            except Exception:
                error_body = {"detail": resp.text}

            # On badNonce, grab the new nonce from the response and retry
            if "badNonce" in error_body.get("type", "") and attempt < _NONCE_RETRIES - 1:
                fresh = resp.headers.get("Replay-Nonce")
                if fresh:
                    current_nonce = fresh
                    continue
                # Fall back to fetching a nonce if the header is missing
                if directory is None:
                    directory = self.get_directory()
                current_nonce = self.get_nonce(directory)
                continue

            raise AcmeError(resp.status_code, error_body, resp.headers.get("Replay-Nonce", ""))

        # Should never reach here, but satisfy the type checker
        raise AcmeError(0, {"detail": "Exceeded nonce retry limit"})

    def _post_jws(
        self,
        url: str,
        jws_body: dict[str, Any],
        accept: str = "application/json",
    ) -> requests.Response:
        """POST a pre-signed JWS body (used by unit tests that build their own body)."""
        resp = self._session.post(
            url,
            json=jws_body,
            headers={
                "Content-Type": "application/jose+json",
                "Accept": accept,
            },
            timeout=self.timeout,
        )
        if not resp.ok:
            try:
                error_body = resp.json()
            except Exception:
                error_body = {"detail": resp.text}
            raise AcmeError(resp.status_code, error_body)
        return resp


def make_client() -> DigiCertAcmeClient:
    """
    Create a DigiCertAcmeClient from the current application settings.
    Late-imports config to avoid circular imports at module load time.
    """
    from config import settings  # noqa: PLC0415

    return DigiCertAcmeClient(
        directory_url=settings.DIGICERT_ACME_DIRECTORY,
        eab_key_id=settings.DIGICERT_EAB_KEY_ID,
        eab_hmac_key=settings.DIGICERT_EAB_HMAC_KEY,
        ca_bundle=settings.ACME_CA_BUNDLE,
        insecure=settings.ACME_INSECURE,
    )
