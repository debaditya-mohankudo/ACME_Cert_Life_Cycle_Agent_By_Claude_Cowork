"""
Static analysis tests for Docker security configuration.

These tests parse Dockerfile and docker-compose.yml to verify that
non-root user and capability hardening settings are present and correct.
No Docker daemon required.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent


# ── helpers ───────────────────────────────────────────────────────────────────

def _production_stage_lines() -> list[str]:
    """Return only the lines that belong to the production stage of the Dockerfile."""
    dockerfile = (ROOT / "Dockerfile").read_text()
    lines = dockerfile.splitlines()

    in_production = False
    stage_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("FROM") and "AS production" in stripped:
            in_production = True
            continue
        # A new FROM line starts the next stage — stop collecting
        if stripped.startswith("FROM") and in_production:
            break
        if in_production:
            stage_lines.append(stripped)

    assert stage_lines, "production stage not found in Dockerfile"
    return stage_lines


def _compose_service() -> dict:
    """Return the acme-agent service dict from docker-compose.yml."""
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    return compose["services"]["acme-agent"]


# ── Dockerfile tests ───────────────────────────────────────────────────────────

class TestDockerfileNonRoot:

    def test_useradd_creates_uid_1001(self):
        """production stage must create system user with UID 1001."""
        lines = _production_stage_lines()
        run_block = " ".join(lines)
        assert "useradd" in run_block, "useradd not found in production stage"
        assert "-u 1001" in run_block, "UID 1001 not set in useradd"

    def test_useradd_is_system_user(self):
        """-r flag makes it a system account (no home dir, no cron job)."""
        lines = _production_stage_lines()
        run_block = " ".join(lines)
        assert "useradd -r" in run_block or "useradd" in run_block and "-r" in run_block

    def test_data_dir_chowned_to_1001(self):
        """production stage must chown /data to UID 1001 before USER switch."""
        lines = _production_stage_lines()
        run_block = " ".join(lines)
        assert "chown" in run_block and "1001" in run_block, (
            "chown to UID 1001 not found — /data will be unwritable at runtime"
        )

    def test_user_directive_is_1001(self):
        """USER directive must be present and set to 1001."""
        lines = _production_stage_lines()
        user_lines = [l for l in lines if l.startswith("USER")]
        assert user_lines, "No USER directive in production stage"
        assert "1001" in user_lines[-1], (
            f"USER directive does not set UID 1001: {user_lines[-1]}"
        )

    def test_user_directive_comes_after_chown(self):
        """USER 1001 must appear after the chown so /data is owned correctly."""
        lines = _production_stage_lines()
        chown_idx = next(
            (i for i, l in enumerate(lines) if "chown" in l and "1001" in l), None
        )
        user_idx = next(
            (i for i, l in enumerate(lines) if l.startswith("USER") and "1001" in l), None
        )
        assert chown_idx is not None, "chown line not found"
        assert user_idx is not None, "USER 1001 line not found"
        assert chown_idx < user_idx, (
            "USER 1001 appears before chown — /data will not be writable at runtime"
        )

    def test_no_user_root_in_production(self):
        """production stage must not switch back to root after USER 1001."""
        lines = _production_stage_lines()
        user_lines = [(i, l) for i, l in enumerate(lines) if l.startswith("USER")]
        # If there are multiple USER directives, the last one must not be root
        if len(user_lines) > 1:
            last_user = user_lines[-1][1]
            assert "root" not in last_user and "0" != last_user.split()[-1], (
                f"Final USER directive in production stage is root: {last_user}"
            )


# ── docker-compose.yml tests ───────────────────────────────────────────────────

class TestComposeCapabilities:

    def test_net_bind_service_is_added(self):
        """cap_add must include NET_BIND_SERVICE to allow port-80 binding as non-root."""
        service = _compose_service()
        cap_add = service.get("cap_add", [])
        assert "NET_BIND_SERVICE" in cap_add, (
            "NET_BIND_SERVICE missing from cap_add — UID 1001 cannot bind port 80"
        )

    def test_all_capabilities_dropped(self):
        """cap_drop must include ALL to minimise the capability surface."""
        service = _compose_service()
        cap_drop = service.get("cap_drop", [])
        assert "ALL" in cap_drop, (
            "cap_drop: ALL missing — container retains default Linux capabilities"
        )

    def test_no_new_privileges(self):
        """security_opt must include no-new-privileges:true."""
        service = _compose_service()
        security_opt = service.get("security_opt", [])
        assert "no-new-privileges:true" in security_opt, (
            "no-new-privileges:true missing from security_opt"
        )

    def test_port_80_still_mapped(self):
        """Port 80 must still be mapped — standalone HTTP-01 challenge requires it."""
        service = _compose_service()
        ports = service.get("ports", [])
        assert any("80:80" in str(p) for p in ports), (
            "Port 80:80 mapping removed — HTTP-01 standalone challenge will fail"
        )

    def test_data_volume_mounted(self):
        """Named volume acme_data must be mounted at /data."""
        service = _compose_service()
        volumes = service.get("volumes", [])
        assert any("/data" in str(v) for v in volumes), (
            "Volume mount at /data missing — certs and account.key will not persist"
        )
