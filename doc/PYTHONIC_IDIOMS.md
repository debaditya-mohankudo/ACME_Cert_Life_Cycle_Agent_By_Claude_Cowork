# Pythonic Idioms & Advanced Patterns Used

This document catalogs Python idioms, design patterns, and advanced language features used throughout the ACME Certificate Lifecycle Agent project. Understanding these patterns is essential for contributing to this codebase.

---

## Table of Contents

1. [TypedDict (Structural Typing)](#1-typeddictstructural-typing)
2. [Pydantic BaseSettings with Custom Validators](#2-pydantic-basesettings-with-custom-validators)
3. [Mixin Pattern (Multiple Inheritance)](#3-mixin-patternmultiple-inheritance)
4. [Abstract Base Classes (ABC) & Inheritance](#4-abstract-base-classes-abc--inheritance)
5. [functools.partial (Partial Function Application)](#5-functoolspartial-partial-function-application)
6. [Protocol Classes (Structural Contracts)](#6-protocol-classesstructural-contracts)
7. [Context Managers (@contextmanager & __enter__/__exit__)](#7-context-managers-contextmanager--__enter__/__exit__)
8. [StateGraph Pattern (LangGraph)](#8-stategraph-pattern-langgraph)
9. [Type Hints & Generics](#9-type-hints--generics)
10. [Callable Classes (Node Pattern)](#10-callable-classesnode-pattern)
11. [Class Methods & Static Methods](#11-class-methods--static-methods)
12. [Dunder Methods (__init__, __call__, __enter__, __exit__)](#12-dunder-methods-__init__-__call__-__enter__-__exit__)
13. [Generator & Yield Patterns](#13-generator--yield-patterns)
14. [Module-Level Singletons](#14-module-level-singletons)
15. [Late Imports (Circular Dependency Avoidance)](#15-late-importscircular-dependency-avoidance)
16. [Factory Pattern with Late Binding](#16-factory-pattern-with-late-binding)
17. [Caching Pattern](#17-caching-pattern)
18. [Atomic File Operations](#18-atomic-file-operations)
19. [LangGraph Message Reducer](#19-langgraph-message-reducer)
20. [Decorator Pattern (Composition Over Inheritance)](#20-decorator-pattern-composition-over-inheritance)

---

## 1. TypedDict (Structural Typing)

**File**: `agent/state.py` (lines 22, 32, 60)

**What it is**: A way to define the structure of dictionaries with type hints. Unlike classes, TypedDict doesn't create a runtime type — it's purely for static type checking.

**Usage in this project**:

```python
# Represents a single domain's certificate record
class CertRecord(TypedDict):
    domain: str
    cert_path: str
    key_path: str
    cert_pem: str
    created_at: str
    expires_at: str

# Represents a multi-domain ACME order (SAN support)
class AcmeOrder(TypedDict):
    order_url: str
    identifiers: List[str]  # All domains in order
    auth_urls: List[str]    # Parallel list of auth URLs
    auth_domains: List[str] # Auth domain for each identifier
    ...

# The complete agent execution state
class AgentState(TypedDict):
    managed_domains: List[str]
    certificate_records: Dict[str, CertRecord]
    current_order: Optional[AcmeOrder]
    messages: Annotated[List[BaseMessage], add_messages]
    ...
```

**Why used here**:
- **LangGraph integration**: StateGraph expects TypedDict to enforce state schema across all nodes
- **Type safety**: Catches state shape errors at type-check time, not runtime
- **Zero overhead**: No runtime objects — pure type hints
- **Serialization-friendly**: LangSmith and checkpointing work seamlessly with dict structures

**Best practices**:
- Use `TypedDict` for message payloads and state containers
- Use `Optional[T]` for fields that may not always be present
- Use `List[T]` for multi-domain support (e.g., SAN certificates)

---

## 2. Pydantic BaseSettings with Custom Validators

**File**: `config.py` (lines 47-185)

**What it is**: Pydantic's `BaseSettings` class provides configuration management with environment variable binding and validation. Custom validators enable complex business logic at configuration time.

**Usage in this project**:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    CA_PROVIDER: str  # digicert | zerossl | letsencrypt | custom
    MANAGED_DOMAINS: List[str]
    HTTP_CHALLENGE_MODE: Literal["standalone", "webroot", "dns"]
    KEY_TYPE: Literal["rsa", "ec"]
    RSA_KEY_SIZE: int = 2048
    EC_CURVE: Literal["secp256r1", "secp384r1"] = "secp256r1"

    # Custom validator: CSV → list conversion with fallback
    @field_validator("MANAGED_DOMAINS", mode="before")
    @classmethod
    def parse_domains(cls, v):
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            return [d.strip() for d in v.split(",")]
        raise ValueError("MANAGED_DOMAINS must be CSV string or list")

    # Cross-field validation: RSA key ≥ 2048 vs EC curves
    @model_validator(mode="after")
    def validate_key_params(self) -> "Settings":
        if self.KEY_TYPE == "rsa" and self.RSA_KEY_SIZE < 2048:
            raise ValueError("RSA key must be ≥ 2048 bits")
        return self

    # EAB credential validation
    @model_validator(mode="after")
    def validate_eab_config(self) -> "Settings":
        eab_required = self.CA_PROVIDER in ("digicert", "zerossl", "sectigo")
        if eab_required and not (self.ACME_EAB_KEY_ID and self.ACME_HMAC_KEY):
            raise ValueError(f"{self.CA_PROVIDER} requires EAB credentials")
        return self
```

**Why used here**:
- **Environment-first design**: Configuration loaded from `.env` and environment variables
- **Validation at startup**: Invalid configs fail fast, not during certificate operations
- **Type coercion**: CSV strings automatically → lists, enums validated
- **Cross-field validation**: Ensure EAB credentials exist before attempting ACME calls

**Best practices**:
- Use `field_validator(mode="before")` for coercion (string → type conversion)
- Use `model_validator(mode="after")` for cross-field checks (dependencies between fields)
- Always validate at configuration boundaries (environment ↔ Python)
- Fail explicitly with descriptive errors

---

## 3. Mixin Pattern (Multiple Inheritance)

**File**: `config.py` (lines 21-44)

**What it is**: A mixin is a class designed to be combined with other classes via multiple inheritance. Mixins add functionality without being instantiated directly.

**Usage in this project**:

```python
# Mixin: Handles JSON parse errors gracefully
class _CommaFallbackMixin:
    @staticmethod
    def prepare_field(value: Any) -> Any:
        if isinstance(value, str):
            try:
                return json.loads(value)  # Try JSON first
            except (json.JSONDecodeError, TypeError):
                return value  # Fall back to raw string
        return value

# CSV from environment: inherits from Pydantic's EnvSettingsSource
class _CSVEnvSource(_CommaFallbackMixin, EnvSettingsSource):
    def prepare_field(self, field_name: str, field: FieldInfo,
                     value: Any, value_is_complex: bool) -> Any:
        prepared = self._CommaFallbackMixin.prepare_field(value)
        if field_name == "MANAGED_DOMAINS" and isinstance(prepared, str):
            return [d.strip() for d in prepared.split(",")]
        return prepared

# CSV from .env file: inherits from Pydantic's DotEnvSettingsSource
class _CSVDotEnvSource(_CommaFallbackMixin, DotEnvSettingsSource):
    # Same prepare_field logic
```

**Why used here**:
- **Composable behavior**: Share fallback logic across multiple source types (env vars vs .env file)
- **DRY principle**: Avoid duplicating JSON/CSV parsing logic
- **Flexible inheritance**: Extend Pydantic's built-in sources without forking

**Best practices**:
- Use mixins for *behavior* (methods), not state (attributes)
- Ensure Method Resolution Order (MRO) is intuitive (`mixin_class, base_class`)
- Avoid diamond inheritance without care for MRO

---

## 4. Abstract Base Classes (ABC) & Inheritance

**File**: `acme/dns_challenge.py` (lines 51-72), `acme/client.py` (lines 41-300)

**What it is**: ABC allows you to define abstract methods that subclasses must implement. Enforces a contract.

**Usage in this project**:

### DNS Provider Abstraction

```python
from abc import ABC, abstractmethod

class DnsProvider(ABC):
    """Abstract interface for DNS record management."""

    @abstractmethod
    def create_txt_record(self, domain: str, txt_value: str) -> None:
        """Create DNS TXT record for ACME challenge."""
        pass

    @abstractmethod
    def delete_txt_record(self, domain: str, txt_value: str) -> None:
        """Delete DNS TXT record after challenge."""
        pass

    @staticmethod
    def _acme_record_name(domain: str) -> str:
        """Convert domain to ACME DNS record name (_acme-challenge.example.com)."""
        return f"_acme-challenge.{domain}"

# Concrete implementations
class CloudflareDnsProvider(DnsProvider):
    def __init__(self, api_token: str, zone_id: str):
        self.api_token = api_token
        self.zone_id = zone_id

    def create_txt_record(self, domain: str, txt_value: str) -> None:
        # Cloudflare API call
        ...

class Route53DnsProvider(DnsProvider):
    def __init__(self, hosted_zone_id: str, region: str):
        self.hosted_zone_id = hosted_zone_id
        self.region = region

    def create_txt_record(self, domain: str, txt_value: str) -> None:
        # AWS Route53 API call
        ...

class GoogleCloudDnsProvider(DnsProvider):
    def __init__(self, project_id: str, zone_name: str):
        self.project_id = project_id
        self.zone_name = zone_name

    def create_txt_record(self, domain: str, txt_value: str) -> None:
        # Google Cloud DNS API call
        ...
```

### ACME Client Hierarchy

```python
class AcmeClient(ABC):
    """Base RFC 8555 ACME client."""

    def __init__(self, directory_url: str, account_key: RSAPrivateKey):
        self.directory_url = directory_url
        self.account_key = account_key
        self._directory_cache = None

    def create_account(self, ...) -> tuple[str, dict]:
        """Create ACME account and return URL + key change response."""
        # Implemented in RFC 8555

class EabAcmeClient(AcmeClient):
    """Shared logic for EAB (External Account Binding) providers."""

    def create_account(self, contact: str, eab_key_id: str,
                      eab_hmac_key: str) -> tuple[str, dict]:
        # EAB-specific account creation
        jws_payload = self._create_eab_jws(eab_key_id, eab_hmac_key)
        # ...

class DigiCertAcmeClient(EabAcmeClient):
    """DigiCert ACME client (EAB required)."""
    directory_url = "https://one.digicert.com/acme/v2"

class ZeroSSLAcmeClient(EabAcmeClient):
    """ZeroSSL ACME client (EAB required)."""
    directory_url = "https://acme.zerossl.com/v2/DV90"

class SectigoAcmeClient(EabAcmeClient):
    """Sectigo ACME client (EAB required)."""
    directory_url = "https://acme.sectigo.com/v2/DV"

class LetsEncryptAcmeClient(AcmeClient):
    """Let's Encrypt ACME client (no EAB)."""
    directory_url = "https://acme-v02.api.letsencrypt.org/directory"
```

**Why used here**:
- **Provider independence**: Swap DNS providers or ACME CAs without changing node logic
- **Contract enforcement**: Abstract methods force all providers to implement required methods
- **Shared behavior**: Base classes (`AcmeClient`, `EabAcmeClient`) eliminate duplicated logic
- **Testability**: Mock implementations satisfy the ABC contract

**Best practices**:
- Use `@abstractmethod` for *required* methods, `@staticmethod` for *utility* methods
- Place shared logic in base classes; subclasses add specifics
- Use `ABC` for top-level contracts, regular classes for shared implementation

---

## 5. functools.partial (Partial Function Application)

**File**: `acme/client.py` (lines 568-618), `acme/dns_challenge.py` (lines 352-369), `acme/http_challenge.py` (line 73)

**What it is**: `functools.partial` creates a new function by pre-filling some arguments of an existing function. Useful for registries and callbacks.

**Usage in this project**:

### ACME Client Registry

The canonical example of this pattern in the codebase is `_client_registry()` in `acme/client.py`. Settings attributes are captured into each `partial` at registry construction time — the caller just picks a key and calls `()`.

```python
from functools import partial

def _client_registry(ca_provider: str, settings: Any) -> AcmeClient:
    """Return the AcmeClient instance for the given CA provider and settings."""

    # Extract shared settings once; each partial captures them by value.
    ca_bundle: str = settings.ACME_CA_BUNDLE
    insecure: bool = settings.ACME_INSECURE

    registry: dict[str, Any] = {
        "digicert": partial(
            DigiCertAcmeClient,
            eab_key_id=settings.ACME_EAB_KEY_ID,
            eab_hmac_key=settings.ACME_EAB_HMAC_KEY,
            ca_bundle=ca_bundle,
            insecure=insecure,
        ),
        "letsencrypt": partial(
            LetsEncryptAcmeClient,
            ca_bundle=ca_bundle,
            insecure=insecure,
        ),
        "letsencrypt_staging": partial(
            LetsEncryptAcmeClient,
            staging=True,          # pre-fill variant flag
            ca_bundle=ca_bundle,
            insecure=insecure,
        ),
        "zerossl": partial(
            ZeroSSLAcmeClient,
            eab_key_id=settings.ACME_EAB_KEY_ID,
            eab_hmac_key=settings.ACME_EAB_HMAC_KEY,
            ca_bundle=ca_bundle,
            insecure=insecure,
        ),
        "sectigo": partial(
            SectigoAcmeClient,
            eab_key_id=settings.ACME_EAB_KEY_ID,
            eab_hmac_key=settings.ACME_EAB_HMAC_KEY,
            ca_bundle=ca_bundle,
            insecure=insecure,
        ),
        "custom": partial(
            AcmeClient,
            directory_url=settings.ACME_DIRECTORY_URL,  # user-supplied URL
            ca_bundle=ca_bundle,
            insecure=insecure,
        ),
    }

    try:
        return registry[ca_provider]()   # call with no args — all pre-filled
    except KeyError:
        raise ValueError(
            f"Unknown CA_PROVIDER: {ca_provider!r}. "
            f"Must be one of: {', '.join(registry.keys())}"
        )


def make_client() -> AcmeClient:
    """Public entry point — reads CA_PROVIDER from settings singleton."""
    from config import settings  # late import: avoids circular dependency
    return _client_registry(settings.CA_PROVIDER, settings)
```

Key properties of this pattern:

| Property | Benefit |
|---|---|
| Settings captured at registry construction | Caller passes no credentials; dispatch is a dict lookup + `()` |
| `partial` over `lambda` | Introspectable (`repr` shows class + bound args); easier to test |
| `ValueError` on unknown key | Caller gets actionable message listing valid options |
| Private `_client_registry` + public `make_client` | Separation of dispatch logic from settings singleton access |

### DNS Provider Registry

```python
def make_dns_provider(mode: str) -> DnsProvider:
    """Factory function using partial for DNS provider instantiation."""

    registry = {
        "cloudflare": partial(
            CloudflareDnsProvider,
            api_token=settings.CLOUDFLARE_API_TOKEN,
            zone_id=settings.CLOUDFLARE_ZONE_ID,
        ),
        "route53": partial(
            Route53DnsProvider,
            hosted_zone_id=settings.AWS_ROUTE53_HOSTED_ZONE_ID,
            region=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        ),
        "google": partial(
            GoogleCloudDnsProvider,
            project_id=settings.GCP_PROJECT_ID,
            zone_name=settings.GCP_ZONE_NAME,
            credentials_json=settings.GCP_CREDENTIALS_JSON,
        ),
    }

    partial_fn = registry[mode]  # Get partial function
    return partial_fn()           # Call with no args (all pre-filled)
```

### HTTP Challenge Handler

```python
# Pre-fill token and key_authorization, create handler for HTTPServer
handler = partial(
    _ChallengeHandler,
    token=token,
    key_authorization=key_authorization,
)
server = HTTPServer(("0.0.0.0", 80), handler)
```

**Why used here**:
- **Configuration baked into callbacks**: Credentials passed to factories at registry construction time, not invocation time
- **Clean registries**: No lambda boilerplate; `partial` is more readable and introspectable
- **Deferred instantiation**: Providers created lazily; credentials injected upfront
- **Testability**: `_client_registry` accepts a settings stub — no singleton needed in unit tests

**Best practices**:
- Use `partial` when you have a factory/registry pattern with configuration
- Prefer `partial` over `lambda` for cleaner code (more readable, introspectable)
- Separate the registry function (`_client_registry`) from the singleton accessor (`make_client`) so tests can inject fake settings
- Raise `ValueError` (not `KeyError`) for unknown keys — include the valid options in the message
- Avoid over-nesting `partial` calls; keep registry setup clear

---

## 6. Protocol Classes (Structural Contracts)

**File**: `agent/nodes/base.py` (lines 1-14)

**What it is**: `typing.Protocol` defines a structural contract without inheritance. If a class implements the required methods/attributes, it satisfies the protocol—regardless of inheritance.

**Usage in this project**:

```python
from typing import Protocol

class NodeCallable(Protocol):
    """Structural contract for node instances accepted by graph registration.

    Any class with a __call__(state: AgentState) -> dict method satisfies
    this protocol, even without explicitly inheriting from it.
    """

    def __call__(self, state: AgentState) -> dict:
        """Execute node logic and return partial state updates.

        Args:
            state: Current agent execution state

        Returns:
            Dictionary of state updates to apply
        """
        ...

# Example: any class matching this signature satisfies NodeCallable
class CertificateScannerNode:
    def __call__(self, state: AgentState) -> dict:
        # Scan local certs, check expiration
        return {"certificate_records": {...}}

class ChallengeSetupNode:
    def __call__(self, state: AgentState) -> dict:
        # Setup HTTP-01 or DNS-01 challenge
        return {"current_order": {...}}

# Both classes satisfy NodeCallable without explicit inheritance
def register_node(callable_node: NodeCallable, name: str):
    graph.add_node(name, callable_node)
```

**Why used here**:
- **Loose coupling**: Nodes don't inherit from a base class; they just implement `__call__`
- **Duck typing with type safety**: Structural compatibility checked at type-check time
- **Flexibility**: Easy to create test mocks that satisfy the protocol

**Best practices**:
- Use `Protocol` for *structural* contracts (behavior), not inheritance hierarchies
- Define required methods with clear docstrings
- Prefer `Protocol` over ABC when inheritance isn't needed

---

## 7. Context Managers (@contextmanager & __enter__/__exit__)

**File**: `mcp_server.py` (lines 77-91), `acme/http_challenge.py` (lines 87-91)

**What it is**: Context managers (via `@contextmanager` or `__enter__`/`__exit__` dunder methods) ensure resources are properly acquired and released, even if exceptions occur.

**Usage in this project**:

### Decorator-Based Context Manager

```python
from contextlib import contextmanager

@contextmanager
def _temporary_settings_override(overrides: dict):
    """Temporarily override Settings singleton for testing.

    Restores original settings on exit, even if an exception occurs.
    """
    original = {}
    for key, value in overrides.items():
        original[key] = getattr(settings, key)
        setattr(settings, key, value)

    try:
        yield  # Context body executes here
    finally:
        # Cleanup always runs
        for key, original_value in original.items():
            setattr(settings, key, original_value)

# Usage:
with _temporary_settings_override({"CA_PROVIDER": "letsencrypt_staging"}):
    # Run tests with staging config
    response = client.create_account(...)
# Settings automatically restored
```

### Class-Based Context Manager

```python
class StandaloneHttpChallenge:
    """Context manager for HTTP-01 challenge server lifecycle."""

    def __init__(self, port: int = 80):
        self.port = port
        self.server = None

    def start(self) -> None:
        """Start HTTP server on port 80."""
        handler = partial(_ChallengeHandler, token=token, key_auth=key_auth)
        self.server = HTTPServer(("0.0.0.0", self.port), handler)
        self.server.serve_forever()  # Blocking

    def stop(self) -> None:
        """Shut down HTTP server."""
        if self.server:
            self.server.shutdown()

    def __enter__(self):
        """Enter context: start server."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context: always stop server."""
        self.stop()
        return False  # Don't suppress exceptions

# Usage:
with StandaloneHttpChallenge(port=80) as challenge:
    # HTTP server is running
    response = verify_challenge(challenge_url)
# Server automatically stopped, even if verify_challenge() raised
```

### Async Context Manager

```python
from contextlib import asynccontextmanager
import asyncio

@asynccontextmanager
async def _operation_lock():
    """Async context manager for concurrent MCP operation protection."""
    async with _OPERATION_LOCK:  # asyncio.Lock
        try:
            yield
        finally:
            # Cleanup
            pass

# Usage:
async def handle_request():
    async with _operation_lock():
        # Only one MCP operation at a time
        await execute_operation()
```

**Why used here**:
- **Resource safety**: HTTP servers, files, locks acquired/released reliably
- **Exception safety**: Cleanup runs even if `try` body fails
- **Test isolation**: Settings overrides restored automatically
- **Readability**: `with` syntax is clearer than manual setup/teardown

**Best practices**:
- Use `@contextmanager` for simple setup/teardown with yield
- Use `__enter__`/`__exit__` for stateful resources (servers, connections)
- Always use `finally` or `try`/`except` to ensure cleanup
- Return `False` from `__exit__` to propagate exceptions

---

## 8. StateGraph Pattern (LangGraph)

**File**: `agent/graph.py` (lines 45-120), `agent/revocation_graph.py` (lines 27-68)

**What it is**: LangGraph's `StateGraph` is a declarative way to build deterministic state machines. Nodes are functions; edges define transitions.

**Usage in this project**:

```python
from langgraph.graph import StateGraph, START, END

def build_graph(settings: Settings) -> CompiledStateGraph:
    """Build the main certificate renewal workflow graph.

    Topology:
    START → planner → certificate_scanner → [domain loop]
    → pick_next_domain → router → [challenge/order/csr/finalize branches]
    → verify_challenge → storage → reporter → END
    """

    builder = StateGraph(AgentState)

    # 1. Plan domains to renew
    builder.add_node("planner", PlannerNode())

    # 2. Scan local certificates
    builder.add_node("certificate_scanner", CertificateScannerNode())

    # 3. Create ACME order
    builder.add_node("order", OrderNode())

    # 4. Setup challenge (HTTP-01 or DNS-01)
    builder.add_node("challenge_setup", ChallengeSetupNode())

    # 5. Verify challenge completed
    builder.add_node("challenge_verify", ChallengeVerifierNode())

    # 6. Generate CSR (Certificate Signing Request)
    builder.add_node("csr", CSRNode())

    # 7. Finalize order with ACME server
    builder.add_node("finalizer", FinalizerNode())

    # 8. Download and store certificate
    builder.add_node("storage", StorageNode())

    # 9. Error handling with retry logic
    builder.add_node("error_handler", ErrorHandlerNode())
    builder.add_node("retry_scheduler", RetrySchedulerNode())

    # 10. Domain routing (pick next domain to process)
    builder.add_node("pick_next_domain", PickNextDomainNode())

    # 11. Reporter: LLM summary
    builder.add_node("reporter", ReporterNode())

    # Linear path for successful renewal
    builder.add_edge(START, "planner")
    builder.add_edge("planner", "certificate_scanner")
    builder.add_edge("certificate_scanner", "pick_next_domain")

    # Conditional routing based on current domain
    builder.add_conditional_edges(
        "pick_next_domain",
        lambda state: "order" if state.get("current_domain") else "reporter",
        {"order": "order", "reporter": "reporter"},
    )

    # Order → challenge → verify → CSR → finalize → storage loop
    builder.add_edge("order", "challenge_setup")
    builder.add_edge("challenge_setup", "challenge_verify")
    builder.add_edge("challenge_verify", "csr")
    builder.add_edge("csr", "finalizer")
    builder.add_edge("finalizer", "storage")

    # Error handler catches failures and decides retry or skip
    builder.add_edge("storage", "error_handler")
    builder.add_conditional_edges(
        "error_handler",
        lambda state: "retry_scheduler" if should_retry(state) else "pick_next_domain",
        {"retry_scheduler": "retry_scheduler", "pick_next_domain": "pick_next_domain"},
    )

    # Retry logic: wait and retry
    builder.add_edge("retry_scheduler", "pick_next_domain")

    # Reporter: final LLM summary
    builder.add_edge("reporter", END)

    # Compile with checkpointing support
    return builder.compile(checkpointer=MemorySaver())
```

**Why used here**:
- **Determinism**: Explicit topology; no hidden control flow
- **Checkpointing**: LangSmith integration for observability and replay
- **Structured error handling**: Errors routed to error_handler node, not scattered through logic
- **Concurrency safety**: Graph ensures sequential ACME operations (no race conditions on nonce)

**Best practices**:
- Define nodes as stateless callables (classes with `__call__`)
- Use conditional edges for branching logic (retry, skip, abort)
- Keep state updates minimal (return only changed fields)
- Document graph topology in docstrings

---

## 9. Type Hints & Generics

**Files**: Throughout (especially `agent/state.py`, `acme/client.py`, `config.py`)

**What it is**: Type hints provide static type checking, IDE autocompletion, and self-documenting code.

**Usage in this project**:

```python
from typing import Optional, List, Dict, Union, Tuple, Callable, Annotated
from typing_extensions import Literal

# Optional types
current_order: Optional[AcmeOrder] = None
certificate_path: Optional[str] = None

# List of strings (multi-domain support)
managed_domains: List[str] = ["example.com", "api.example.com"]
auth_urls: List[str]  # Parallel list matching identifiers

# Dictionary mapping (per-domain state)
certificate_records: Dict[str, CertRecord]
auth_metadata: Dict[str, dict] = {}

# Union types (multiple valid types)
key_material: Union[RSAPrivateKey, EllipticCurvePrivateKey]

# Tuple return types
def create_account(...) -> Tuple[str, dict]:
    account_url = "https://acme.example.com/acme/acct/123"
    key_change_response = {...}
    return account_url, key_change_response

# Literal types (restricted enum-like values)
challenge_mode: Literal["standalone", "webroot", "dns"]
ca_provider: Literal["digicert", "zerossl", "letsencrypt", "custom"]

# Callable types (function signatures)
router_fn: Callable[[AgentState], str]  # Takes state, returns route name

# Annotated types (metadata for frameworks)
from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages

messages: Annotated[List[BaseMessage], add_messages]
```

**Why used here**:
- **IDE support**: Autocomplete and inline type checking
- **Static analysis**: mypy/pyright catch type errors before runtime
- **Documentation**: Type hints are executable documentation
- **LangGraph integration**: Annotated types support framework conventions (e.g., `add_messages`)

**Best practices**:
- Always annotate function parameters and return types
- Use `Optional[T]` for nullable fields
- Use `Literal[...]` for enum-like values instead of plain strings
- Use `Annotated[T, metadata]` for framework-specific behavior (e.g., LangGraph reducers)

---

## 10. Callable Classes (Node Pattern)

**File**: `agent/nodes/*.py` (14+ node classes)

**What it is**: Classes with a `__call__` method become callable, allowing instances to be used as functions. This enables stateful callbacks.

**Usage in this project**:

```python
class CertificateScannerNode:
    """Scan local certificate storage and determine renewal candidates."""

    def __call__(self, state: AgentState) -> dict:
        """Execute node logic.

        Args:
            state: Current agent state

        Returns:
            Partial state update dict
        """
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        """Actual implementation logic."""
        cert_store = Path(state["cert_store_path"])
        records = {}

        for domain in state["managed_domains"]:
            cert_path = cert_store / f"{domain}.crt"
            if cert_path.exists():
                cert_pem = cert_path.read_text()
                cert = x509.load_pem_x509_certificate(cert_pem.encode())

                expires_at = cert.not_valid_after_utc
                days_left = (expires_at - datetime.now(timezone.utc)).days

                records[domain] = CertRecord(
                    domain=domain,
                    cert_path=str(cert_path),
                    key_path=str(cert_store / f"{domain}.key"),
                    cert_pem=cert_pem,
                    created_at=cert.not_valid_before_utc.isoformat(),
                    expires_at=expires_at.isoformat(),
                )

        return {"certificate_records": records}

# Node registry
NODE_REGISTRY = {
    "certificate_scanner": CertificateScannerNode,
    "order": OrderNode,
    "challenge_setup": ChallengeSetupNode,
    ...
}

# Usage in graph
def build_graph():
    builder = StateGraph(AgentState)

    for node_name, node_class in NODE_REGISTRY.items():
        node_instance = node_class()  # Instantiate
        builder.add_node(node_name, node_instance)  # Register callable
```

**Why used here**:
- **State isolation**: Each node instance can maintain internal state (if needed)
- **Testability**: Mock node instances that satisfy `NodeCallable` protocol
- **Registry pattern**: Node classes stored in registry; instances created once and reused
- **Introspection**: LangGraph can call `__call__` on any instance

**Best practices**:
- Implement `__call__(state: AgentState) -> dict` for LangGraph nodes
- Keep `__call__` thin; move logic to helper methods (e.g., `run()`)
- Return only changed state fields, not the entire state

---

## 11. Class Methods & Static Methods

**File**: `config.py` (lines 125-166), `acme/dns_challenge.py` (lines 69-72)

**What it is**: Class methods operate on the class itself (not instances); static methods are utility functions without access to class or instance state.

**Usage in this project**:

### Class Methods (Pydantic Validators)

```python
class Settings(BaseSettings):
    MANAGED_DOMAINS: List[str]
    HTTP_CHALLENGE_MODE: Literal["standalone", "webroot", "dns"]

    # Class method: Pydantic calls this during initialization
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: SettingsSource,
        env_settings: SettingsSource,
        dotenv_settings: SettingsSource,
        file_secret_settings: SettingsSource,
    ) -> tuple[SettingsSource, ...]:
        """Define order of settings sources.

        Priority: init args → environment → .env file → secrets
        """
        return (
            init_settings,
            _CSVEnvSource(env_settings),      # Custom env handling
            _CSVDotEnvSource(dotenv_settings), # Custom .env handling
            file_secret_settings,
        )

    # Class method: Field validator
    @field_validator("MANAGED_DOMAINS", mode="before")
    @classmethod
    def parse_domains(cls, v):
        """Convert CSV string to list."""
        if isinstance(v, str):
            return [d.strip() for d in v.split(",")]
        return v

    # Class method: Model validator
    @model_validator(mode="after")
    def validate_eab_config(self) -> "Settings":
        """Cross-field validation."""
        if self.CA_PROVIDER in ("digicert", "zerossl") and not self.ACME_EAB_KEY_ID:
            raise ValueError("EAB credentials required")
        return self
```

### Static Methods (Utility Functions)

```python
class DnsProvider(ABC):
    """Base DNS provider."""

    @staticmethod
    def _acme_record_name(domain: str) -> str:
        """Convert domain to ACME challenge DNS name.

        Example: example.com → _acme-challenge.example.com

        Note: @staticmethod because this is a utility, not dependent on
        instance or class state.
        """
        return f"_acme-challenge.{domain}"

# Usage
record_name = DnsProvider._acme_record_name("example.com")
# → "_acme-challenge.example.com"
```

**Why used here**:
- **Class methods**: Pydantic integration; called during model initialization
- **Static methods**: Utility functions that logically belong to a class but don't need access to state
- **Clarity**: `@classmethod` and `@staticmethod` signal intent; readers know these aren't instance methods

**Best practices**:
- Use `@classmethod` for alternative constructors and Pydantic validators
- Use `@staticmethod` for pure utility functions (e.g., `_acme_record_name()`)
- Avoid `@staticmethod` if the logic doesn't logically belong to the class

---

## 12. Dunder Methods (__init__, __call__, __enter__, __exit__)

**Files**: Multiple (see Section 7 for context managers)

**What it is**: Special methods (surrounded by double underscores) that implement Python language features.

**Usage in this project**:

### __init__ (Constructor)

```python
class StandaloneHttpChallenge:
    """HTTP-01 challenge server."""

    def __init__(self, port: int = 80, token: str, key_auth: str):
        """Initialize HTTP server with challenge token and key auth.

        Args:
            port: Listening port (default 80 for HTTP)
            token: ACME challenge token
            key_auth: Key authorization (RFC 8555 §8.1)
        """
        self.port = port
        self.token = token
        self.key_auth = key_auth
        self.server: Optional[HTTPServer] = None
```

### __call__ (Make Objects Callable)

```python
class ChallengeSetupNode:
    """Setup phase for ACME challenge (HTTP-01 or DNS-01)."""

    def __call__(self, state: AgentState) -> dict:
        """LangGraph calls this as a node function.

        Args:
            state: Current execution state

        Returns:
            State updates
        """
        mode = state["http_challenge_mode"]

        if mode == "standalone":
            self._setup_http_standalone(state)
        elif mode == "dns":
            self._setup_dns(state)

        return {"challenge_setup_complete": True}

    def _setup_http_standalone(self, state: AgentState) -> None:
        """Start HTTP server for HTTP-01."""
        ...
```

### __enter__ and __exit__ (Context Manager Protocol)

```python
class StandaloneHttpChallenge:
    """Context manager for HTTP server lifecycle."""

    def __enter__(self):
        """Enter context: start HTTP server."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context: stop server (always runs, even on exception)."""
        self.stop()
        return False  # Don't suppress exceptions

# Usage
with StandaloneHttpChallenge(port=80, token="...", key_auth="...") as server:
    # Server is running; respond to ACME challenge requests
    verify_challenge(challenge_url)
# Server automatically stopped
```

### Other Common Dunders

```python
class AcmeOrder(TypedDict):
    """ACME order (immutable dict-like object)."""

    def __repr__(self) -> str:
        """Custom string representation for debugging."""
        return f"AcmeOrder(order_url={self.order_url!r}, identifiers={self.identifiers!r})"

    def __len__(self) -> int:
        """Number of identifiers (domains) in order."""
        return len(self.identifiers)
```

**Why used here**:
- **__init__**: Required for all classes; initializes instance state
- **__call__**: Makes node instances callable; LangGraph expects nodes to be callable
- **__enter__/__exit__**: Ensure resources (servers, connections) are properly managed
- **__repr__**: Better debugging output; shows structure at a glance

**Best practices**:
- Always implement `__repr__` for custom classes (helps debugging)
- Implement `__call__` for classes used as callbacks (e.g., LangGraph nodes)
- Implement `__enter__/__exit__` for resource management
- Never raise exceptions in `__exit__` unless you want to suppress the original exception

---

## 13. Generator & Yield Patterns

**File**: `mcp_server.py` (lines 77-91 with `@contextmanager`)

**What it is**: Generators are functions that use `yield` to produce values lazily. The `@contextmanager` decorator converts a generator into a context manager.

**Usage in this project**:

```python
from contextlib import contextmanager

@contextmanager
def _temporary_settings_override(overrides: dict):
    """Temporarily modify Settings singleton for testing.

    Generator-based context manager:
    1. Setup code runs before yield
    2. yield pauses execution; caller enters context body
    3. Cleanup code runs after yield (in finally block)
    """
    # Setup: Save original values
    original = {}
    for key, value in overrides.items():
        original[key] = getattr(settings, key)
        setattr(settings, key, value)

    try:
        yield  # Pause here; context body executes
    finally:
        # Cleanup: Restore original values (always runs, even on exception)
        for key, original_value in original.items():
            setattr(settings, key, original_value)

# Usage:
def test_digicert_renewal():
    with _temporary_settings_override({"CA_PROVIDER": "digicert"}):
        # Inside context: settings.CA_PROVIDER == "digicert"
        response = create_account()
        assert response.status_code == 201
    # After context: settings.CA_PROVIDER restored to original value
```

**Why used here**:
- **Concise context managers**: Avoid boilerplate `__enter__`/`__exit__` for simple setup/cleanup
- **Readable**: Linear code flow; setup and cleanup adjacent
- **Exception-safe**: `finally` block runs even if context body raises

**Best practices**:
- Use `@contextmanager` for one-time setup/teardown
- Use class-based context managers for stateful resources (e.g., server sockets)
- Always wrap in `try`/`finally` to ensure cleanup
- Avoid complex logic; generators are for simple setup/cleanup patterns

---

## 14. Module-Level Singletons

**File**: `agent/nodes/challenge.py` (lines 34-37)

**What it is**: Module-level variables that act as singletons, shared across function calls within the module.

**Usage in this project**:

```python
# agent/nodes/challenge.py

# Singletons: kept alive across setup → verify phases
_standalone_server: StandaloneHttpChallenge | None = None
_dns_provider: DnsProvider | None = None

class ChallengeSetupNode:
    """Setup challenge (HTTP-01 or DNS-01)."""

    def __call__(self, state: AgentState) -> dict:
        global _standalone_server, _dns_provider

        mode = state["http_challenge_mode"]

        if mode == "standalone":
            # Create and store server instance globally
            _standalone_server = StandaloneHttpChallenge(
                port=80,
                token=state["current_token"],
                key_auth=state["current_key_auth"],
            )
            _standalone_server.start()
        elif mode == "dns":
            # Create and store DNS provider globally
            _dns_provider = make_dns_provider(state)
            _dns_provider.create_txt_record(
                domain=state["current_domain"],
                txt_value=state["current_dns_txt_value"],
            )

        return {"challenge_setup_complete": True}

class ChallengeVerifierNode:
    """Verify challenge completion."""

    def __call__(self, state: AgentState) -> dict:
        global _standalone_server, _dns_provider

        # Access singletons created in setup phase
        if _standalone_server:
            _standalone_server.stop()
            _standalone_server = None
        elif _dns_provider:
            _dns_provider.delete_txt_record(
                domain=state["current_domain"],
                txt_value=state["current_dns_txt_value"],
            )
            _dns_provider = None

        return {"challenge_verified": True}
```

**Why used here**:
- **Lifespan management**: HTTP server must persist from setup → verify phases; module-level variable bridges the gap
- **Node statelessness**: Nodes themselves are stateless; singletons are external state
- **Single challenge at a time**: Sequential domain processing ensures only one server/provider exists

**⚠️ Caution**:
- Module singletons reduce testability; requires cleanup between tests
- Not thread-safe; works only in single-threaded context
- Only acceptable here because ACME operations are deliberately sequential

**Best practices**:
- Use module-level singletons sparingly; prefer dependency injection
- Document the purpose and lifespan clearly
- Ensure cleanup is guaranteed (use context managers or try/finally)
- Consider `threading.local()` or `contextvars.ContextVar()` for thread-safe alternatives

---

## 15. Late Imports (Circular Dependency Avoidance)

**File**: `acme/dns_challenge.py` (line 389), `mcp_server.py` (lines 82, 98, 144)

**What it is**: Importing modules inside functions instead of at the top level. Avoids circular imports and defers module initialization.

**Usage in this project**:

```python
# acme/dns_challenge.py

def make_dns_provider(mode: str) -> DnsProvider:
    """Factory function for DNS provider instantiation.

    Uses late import to avoid circular dependency:
    - dns_challenge imports config (for settings)
    - config imports other modules that might import dns_challenge
    """

    # Late import: deferred until function call
    from config import settings

    if mode == "cloudflare":
        return CloudflareDnsProvider(
            api_token=settings.CLOUDFLARE_API_TOKEN,
            zone_id=settings.CLOUDFLARE_ZONE_ID,
        )
    elif mode == "route53":
        return Route53DnsProvider(
            hosted_zone_id=settings.AWS_ROUTE53_HOSTED_ZONE_ID,
            region=settings.AWS_REGION,
        )
    # ...

# mcp_server.py

async def handle_certificate_request(domain: str) -> str:
    """Handle MCP certificate request.

    Uses late import to defer Pydantic model loading.
    """

    # Late import: loaded only when needed
    from acme.client import make_acme_client
    from config import settings

    client = make_acme_client(settings.CA_PROVIDER)
    # ...
```

**Why used here**:
- **Avoid circular imports**: `config` → `dns_challenge` → `config` would fail without late imports
- **Performance**: Expensive modules (Pydantic, crypto libraries) loaded only when used
- **Testing**: Mock imports more easily in test setup

**Best practices**:
- Use late imports to break circular dependency cycles
- Late imports in functions are OK; late imports in class definitions can be confusing
- Document why the late import is necessary
- Avoid excessive late imports; they hurt readability

**Anti-pattern**:
```python
# ❌ Don't do this in every function
def some_function():
    from collections import defaultdict  # Too much overhead; import at top level
    return defaultdict(list)
```

---

## 16. Factory Pattern with Late Binding

**File**: `llm/factory.py` (lines 15-65), `acme/client.py` (lines 568-627), `acme/dns_challenge.py` (lines 350-394)

**What it is**: A factory function that selects and instantiates objects based on runtime configuration. "Late binding" means the selection happens at call time, not definition time.

### Strategy 1: Registry Pattern with functools.partial

**Modern approach** (recommended): Use a registry dict mapping provider names to `functools.partial` constructors. Cleanly separates instantiation logic from dispatch.

```python
# llm/factory.py (refactored)
from functools import partial

def _llm_kwargs_registry(provider: str, api_key: str, base_url: str, max_tokens: int) -> dict[str, Any]:
    """Return provider-specific kwargs dict."""
    registry: dict[str, Any] = {
        "anthropic": {
            "api_key": api_key,
            "max_tokens": max_tokens,
        },
        "openai": {
            "api_key": api_key,
            "max_tokens": max_tokens,
        },
        "ollama": {
            "base_url": base_url,
            "num_predict": max_tokens,
        },
    }
    if provider not in registry:
        raise ValueError(f"Unsupported LLM_PROVIDER: {provider!r}. Must be one of: {', '.join(registry.keys())}")
    return registry[provider]

def make_llm(model: str, max_tokens: int) -> BaseChatModel:
    """Factory: Create LLM instance based on LLM_PROVIDER setting."""
    provider = settings.LLM_PROVIDER
    
    # Validate required API keys
    if provider == "anthropic":
        if not settings.ANTHROPIC_API_KEY:
            raise ValueError("ANTHROPIC_API_KEY must be set when LLM_PROVIDER='anthropic'")
    elif provider == "openai":
        if not settings.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY must be set when LLM_PROVIDER='openai'")
    
    # Get provider-specific kwargs from registry
    kwargs = _llm_kwargs_registry(
        provider=provider,
        api_key=settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY,
        base_url=settings.OLLAMA_BASE_URL,
        max_tokens=max_tokens,
    )
    return init_chat_model(model, model_provider=provider, **kwargs)
```

### Parallel implementations in this project:

**ACME Client Registry** (`acme/client.py`):
```python
def _client_registry(ca_provider: str, settings: Any) -> AcmeClient:
    """Return the AcmeClient instance for the given CA provider."""
    ca_bundle = settings.ACME_CA_BUNDLE
    insecure = settings.ACME_INSECURE
    registry = {
        "digicert": partial(
            DigiCertAcmeClient,
            eab_key_id=settings.ACME_EAB_KEY_ID,
            eab_hmac_key=settings.ACME_EAB_HMAC_KEY,
            ca_bundle=ca_bundle,
            insecure=insecure,
        ),
        "letsencrypt": partial(
            LetsEncryptAcmeClient,
            ca_bundle=ca_bundle,
            insecure=insecure,
        ),
        # ... more providers
    }
    try:
        return registry[ca_provider]()
    except KeyError:
        raise ValueError(f"Unknown CA_PROVIDER: {ca_provider!r}. Must be one of: {', '.join(registry.keys())}")

def make_client() -> AcmeClient:
    """Instantiate the right AcmeClient subclass based on CA_PROVIDER setting."""
    from config import settings
    return _client_registry(settings.CA_PROVIDER, settings)
```

**DNS Provider Registry** (`acme/dns_challenge.py`):
```python
def _dns_provider_registry(provider_name: str, settings: Settings) -> DnsProvider:
    """Return the DNS provider instance for the given name and settings."""
    registry = {
        "cloudflare": partial(
            CloudflareDnsProvider,
            api_token=settings.CLOUDFLARE_API_TOKEN,
            zone_id=settings.CLOUDFLARE_ZONE_ID,
        ),
        "route53": partial(
            Route53DnsProvider,
            hosted_zone_id=settings.AWS_ROUTE53_HOSTED_ZONE_ID,
            region=settings.AWS_REGION,
            access_key_id=settings.AWS_ACCESS_KEY_ID,
            secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        ),
        # ... more providers
    }
    try:
        return registry[provider_name]()
    except KeyError:
        raise ValueError(f"Unknown DNS_PROVIDER: {provider_name!r}. Must be one of: {', '.join(registry.keys())}")

def make_dns_provider() -> DnsProvider:
    """Instantiate and return the configured DNS provider."""
    from config import settings
    return _dns_provider_registry(settings.DNS_PROVIDER, settings)
```

**Why used here**:
- **Configuration-driven**: Provider selected via environment variables
- **No hardcoded dependencies**: Nodes don't import specific provider classes
- **Easy testing**: Mock factories once; all nodes use the mock
- **Flexible**: Swap providers with one config change
- **Registry-based approach**:
  - Uses `functools.partial` to pre-fill constructor arguments
  - Dictionary dispatch is faster and clearer than if-elif chains
  - Extends naturally: adding a provider = adding one registry entry
  - Error messages list all available options automatically

**Best practices**:
- Use registry pattern for multiple pluggable implementations
- Separate validation (API keys) from instantiation (registry)
- Use `functools.partial` to bind constructor args at registry-definition time
- Raise `ValueError` with available options for unknown providers
- Keep the public factory function thin; do the heavy lifting in `_registry` helper

---

## 17. Caching Pattern

**File**: `acme/client.py` (lines 62, 73-83)

**What it is**: Store computed values to avoid re-computing on subsequent calls.

**Usage in this project**:

```python
class AcmeClient:
    """ACME client with cached directory lookup."""

    def __init__(self, directory_url: str, account_key: RSAPrivateKey):
        self.directory_url = directory_url
        self.account_key = account_key
        self._session = requests.Session()

        # Cache: avoid re-fetching directory on every operation
        self._directory_cache: Optional[dict] = None

    def get_directory(self) -> dict:
        """Fetch ACME server directory (RFC 8555 §7.1).

        Caches result; subsequent calls return cached dict.
        """

        # Check cache first
        if self._directory_cache is not None:
            return self._directory_cache

        # Cache miss: fetch from server
        response = self._session.get(
            self.directory_url,
            timeout=self.timeout,
        )
        response.raise_for_status()

        self._directory_cache = response.json()
        return self._directory_cache
```

**Why used here**:
- **Performance**: Directory is static per ACME server; no reason to re-fetch
- **Reduced network traffic**: One HTTP request per client instance, not per operation
- **Determinism**: Same directory dict returned on every call

**Best practices**:
- Cache immutable data (e.g., ACME directory)
- Document cache behavior clearly
- Consider cache invalidation (when to refresh?)
- Use `functools.lru_cache` for pure functions

---

## 18. Atomic File Operations

**File**: `storage/atomic.py` (lines 19-87)

**What it is**: Write to temporary file, sync to disk, then atomically rename. Ensures data consistency even if the process crashes mid-write.

**Usage in this project**:

```python
import os
import tempfile
from pathlib import Path

def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Atomically write text to file.

    Pattern:
    1. Write to temp file
    2. Flush and fsync to disk
    3. Atomically rename temp file to destination

    If process crashes at step 2, temp file is left; no corrupted data file.

    Args:
        path: Destination file path
        content: Content to write
        encoding: Text encoding (default UTF-8)
    """

    # Create temporary file in same directory (same filesystem)
    fd, temp_path = tempfile.mkstemp(
        suffix=".tmp",
        dir=path.parent,
    )

    try:
        # Write content
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()  # Flush to OS buffer
            os.fsync(f.fileno())  # Force write to disk

        # Atomic rename (on POSIX systems)
        os.replace(temp_path, path)

    except Exception:
        # Cleanup temp file on error
        os.unlink(temp_path)
        raise

# Usage
def save_certificate(domain: str, cert_pem: str, key_pem: str) -> None:
    """Save certificate and key atomically."""

    cert_path = Path(f"certs/{domain}.crt")
    key_path = Path(f"certs/{domain}.key")

    # Both writes are atomic; no partial/corrupted files
    atomic_write_text(cert_path, cert_pem)
    atomic_write_text(key_path, key_pem)
```

**Why used here**:
- **Data integrity**: Certificate files never left in partial/corrupted state
- **No race conditions**: Atomic rename ensures file either old or new; no in-between state
- **Crash-safe**: If process crashes mid-write, temp file left; data file untouched

**Best practices**:
- Always create temp file in same directory (same filesystem; ensures atomic rename)
- Call `fsync()` to ensure data reaches disk before rename
- Clean up temp file on error
- Use on any critical writes (certificates, config, state)

---

## 20. Decorator Pattern (Composition Over Inheritance)

**File**: `logger.py` (lines 6-68)

**What it is**: The decorator pattern allows behavior to be added to objects dynamically by wrapping them in decorator objects. It's a structural pattern that uses composition instead of inheritance to extend functionality.

**Usage in this project**:

```python
class RunIDFilter(logging.Filter):
    """Filter that injects run_id into log records."""
    
    def __init__(self, run_id: str):
        super().__init__()
        self.run_id = run_id
    
    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = self.run_id
        return True


class LoggerDecorator:
    """
    Decorator that wraps a standard logger with run_id tracking.
    
    Uses the decorator pattern to extend logging.Logger behavior
    without inheritance, maintaining loose coupling.
    """
    
    def __init__(self, logger: logging.Logger, run_id: str):
        self._logger = logger  # Wrapped object
        self.run_id = run_id
        self._configure()
    
    def _configure(self) -> None:
        """Configure the wrapped logger with run_id filter and formatter."""
        self._logger.setLevel(logging.INFO)
        run_id_filter = RunIDFilter(self.run_id)
        self._logger.addFilter(run_id_filter)
        # ... add handler with custom format
    
    # Delegate logging methods to wrapped logger
    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.info(msg, *args, **kwargs)
    
    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.error(msg, *args, **kwargs)
    # ... other methods


class LoggerWithRunID:
    """Singleton facade for LoggerDecorator."""
    
    def __init__(self, name: str = "agent"):
        if not hasattr(self, "initialized"):
            run_id = str(uuid.uuid4())
            self.logger = logging.getLogger(name)
            self._decorator = LoggerDecorator(self.logger, run_id)  # Composition
            self.initialized = True
    
    # Delegate to decorator
    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._decorator.info(msg, *args, **kwargs)
```

**Why used here**:
- **Loose coupling**: LoggerDecorator wraps logging.Logger without inheriting from it
- **Single responsibility**: RunIDFilter handles run_id injection; LoggerDecorator handles configuration and delegation
- **Extensible**: Easy to add more decorators (e.g., MetricsDecorator, FileLoggerDecorator) by stacking them
- **Testable**: Each layer can be tested independently
- **No inheritance complexity**: Avoids diamond problem and method resolution order issues

**Pattern structure**:
1. **Component** (`logging.Logger`) — the object being wrapped
2. **Decorator** (`LoggerDecorator`) — wraps the component and adds behavior
3. **Concrete decorator** (`RunIDFilter`) — specific enhancement (run_id injection)
4. **Client** (`LoggerWithRunID`) — uses the decorator

**Best practices**:
- Store wrapped object in private attribute (`self._logger`)
- Delegate all interface methods to wrapped object
- Add new behavior in decorator without modifying wrapped object
- Can stack multiple decorators: `MetricsDecorator(LoggerDecorator(base_logger))`
- Prefer composition over inheritance when extending third-party classes

**Contrast with inheritance**:
```python
# ❌ Inheritance approach (tight coupling)
class LoggerWithRunID(logging.Logger):
    def __init__(self, name, run_id):
        super().__init__(name)
        # Tightly coupled to logging.Logger internals

# ✅ Decorator pattern (loose coupling)
class LoggerDecorator:
    def __init__(self, logger: logging.Logger, run_id: str):
        self._logger = logger  # Composition, not inheritance
```

**Related patterns**:
- Used with [Module-Level Singletons](#14-module-level-singletons) for global logger instance
- Combines [Protocol Classes](#6-protocol-classesstructural-contracts) for type safety
- Complements [Abstract Base Classes](#4-abstract-base-classes-abc--inheritance) when interface inheritance is needed

---

## 19. LangGraph Message Reducer

**File**: `agent/state.py` (line 79)

**What it is**: `Annotated` metadata tells LangGraph how to merge messages. The `add_messages` reducer appends new messages to the list, avoiding duplicates.

**Usage in this project**:

```python
from typing import Annotated, List
from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages

class AgentState(TypedDict):
    """Complete execution state."""

    # Messages reducer: automatically merge new messages
    messages: Annotated[List[BaseMessage], add_messages]

    # Other fields
    managed_domains: List[str]
    certificate_records: Dict[str, CertRecord]
    current_order: Optional[AcmeOrder]
    # ...

# Usage in nodes
class PlannerNode:
    def __call__(self, state: AgentState) -> dict:
        # LLM generates a message
        llm = make_llm(...)
        response = llm.invoke(prompt)  # Returns AIMessage

        # Return partial state update
        return {
            "messages": [response],  # LangGraph's add_messages reduces this
        }

# How add_messages works:
# Before: messages = [HumanMessage("Renew example.com")]
# Node returns: {"messages": [AIMessage("Renewing..."]}
# After: messages = [HumanMessage(...), AIMessage(...)]
# (Old messages preserved, new message appended)
```

**Why used here**:
- **Conversation history**: Preserve all messages across node executions
- **LLM context**: Pass full conversation history to next LLM node
- **No manual list management**: `add_messages` handles appending automatically
- **Avoid duplicates**: Messages reducer prevents identical messages from being added twice

**Best practices**:
- Use `Annotated[List[BaseMessage], add_messages]` for message lists in LangGraph
- Return `{"messages": [new_message]}` from nodes, not the full list
- LangGraph handles merging; don't manually append to messages

---

## Summary Table

| Pattern | Benefit | Key Files | Risk/Limitation |
|---------|---------|-----------|-----------------|
| **TypedDict** | State schema validation, type safety | `agent/state.py` | No runtime object |
| **Pydantic Settings** | Config management, env var binding | `config.py` | Complexity with validators |
| **Mixin** | Reusable behavior, DRY | `config.py` | MRO complexity if abused |
| **ABC** | Contract enforcement, extensibility | `acme/dns_challenge.py`, `acme/client.py` | Must implement all methods |
| **functools.partial** | Pre-fill callback args, registries | `acme/client.py` (`_client_registry`), `acme/dns_challenge.py` (`_dns_provider_registry`), `llm/factory.py` | Less readable than `lambda` to some |
| **Registry Pattern** | Provider selection via dict dispatch | `acme/client.py`, `acme/dns_challenge.py`, `llm/factory.py` | One more level of indirection |
| **Protocol** | Structural contracts, duck typing | `agent/nodes/base.py` | No runtime enforcement |
| **Context Manager** | Resource safety, cleanup guarantee | `mcp_server.py`, `acme/http_challenge.py` | More complex than simple functions |
| **StateGraph** | Deterministic workflows, observability | `agent/graph.py`, `agent/revocation_graph.py` | Requires graph topology planning |
| **Type Hints** | IDE support, static checking, docs | Throughout | Runtime overhead negligible |
| **Callable Classes** | Stateful callbacks, testability | `agent/nodes/*.py` | Must implement `__call__` |
| **Class/Static Methods** | Pydantic integration, utilities | `config.py`, `acme/dns_challenge.py` | Easy to misuse (e.g., `@staticmethod` vs `@classmethod`) |
| **Dunder Methods** | Language integration, expressiveness | Multiple | Performance overhead if abused |
| **Generators + @contextmanager** | Concise context managers | `mcp_server.py` | Less flexible than class-based |
| **Module Singletons** | Lifespan management | `agent/nodes/challenge.py` | Reduces testability, not thread-safe |
| **Late Imports** | Break circular deps, defer loading | `acme/dns_challenge.py`, `mcp_server.py` | Hurts readability if overused |
| **Factory Pattern** | Configuration-driven instantiation with registry | `llm/factory.py`, `acme/client.py`, `acme/dns_challenge.py` | Indirection; harder to trace |
| **Caching** | Performance, reduced I/O | `acme/client.py` | Must handle invalidation |
| **Atomic I/O** | Data integrity, crash-safety | `storage/atomic.py` | More code; slightly slower |
| **Message Reducer** | Automatic list merging, LangGraph integration | `agent/state.py` | LangGraph-specific |

---

## When to Use Each Pattern

### Configuration & Settings
- **Pydantic BaseSettings** for environment-driven config
- **Mixin** for shared validation logic across setting sources
- **@classmethod** for alternative constructors

### ACME Protocol & Extensibility
- **ABC** for provider abstraction (DNS, ACME CAs, LLM)
- **functools.partial** + **Registry Pattern** for provider instantiation
  - `_client_registry(ca_provider, settings)` → appropriate ACME client
  - `_dns_provider_registry(dns_provider, settings)` → appropriate DNS provider
  - `_llm_kwargs_registry(llm_provider, api_key, base_url, max_tokens)` → LLM kwargs dict
- **Factory Pattern** combines registry dispatch with validation for pluggable components

### State & Workflows
- **TypedDict** for state schemas
- **StateGraph** for deterministic workflows
- **Annotated + add_messages** for message history

### Testing & Flexibility
- **Protocol** for structural contracts
- **@contextmanager** for test fixtures
- **Late imports** to avoid circular dependencies

### Resource Management
- **Context Manager** (class-based) for servers, connections
- **@contextmanager** for simple setup/teardown
- **Module Singletons** only when lifespan spans multiple nodes (rare)

### Data Safety
- **Atomic file I/O** for critical writes (certs, keys, state)

---

## References

- **PEP 544 — Protocols**: https://peps.python.org/pep-0544/
- **PEP 526 — Syntax for Variable Annotations**: https://peps.python.org/pep-0526/
- **Python context managers**: https://docs.python.org/3/library/contextlib.html
- **Pydantic Settings**: https://docs.pydantic.dev/latest/concepts/pydantic_settings/
- **LangGraph**: https://langchain-ai.github.io/langgraph/
- **ABC module**: https://docs.python.org/3/library/abc.html
- **functools.partial**: https://docs.python.org/3/library/functools.html#functools.partial

