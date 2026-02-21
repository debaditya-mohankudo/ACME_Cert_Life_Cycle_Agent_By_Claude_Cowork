# Certificate Storage Layout

Each renewed domain gets its own subdirectory:

```
./certs/api.example.com/
├── cert.pem        # Leaf certificate (end-entity only)
├── chain.pem       # Intermediate CA chain
├── fullchain.pem   # cert.pem + chain.pem — use this in nginx/apache
├── privkey.pem     # RSA-2048 private key (mode 0o600)
└── metadata.json   # {"issued_at", "expires_at", "acme_order_url", "renewed_by"}
```

Point your web server at `fullchain.pem` and `privkey.pem`:

```nginx
ssl_certificate     /path/to/certs/api.example.com/fullchain.pem;
ssl_certificate_key /path/to/certs/api.example.com/privkey.pem;
```

---

## Atomic Writes for Data Safety

All PEM file writes are **atomic** to prevent corruption from crashes, power failures, or disk errors.

### Pattern

1. **Write to temp file** in same directory (same filesystem)
2. **fsync()** to flush to disk
3. **os.replace()** to atomically rename temp → target

### Why It Matters

Without atomic writes, a crash during file write leaves corrupt files:

```
Process writes cert.pem
  [wrote 2048 / 4096 bytes]
  [CRASH]
cert.pem on disk: truncated/corrupt ← Application sees invalid cert!
```

With atomic writes:

```
Process writes .cert.pem.XXXXXX.tmp
  [wrote 4096 bytes]
  [fsync() → disk]
  [os.replace() → atomic rename]
cert.pem on disk: intact, valid, or unchanged ← Always consistent!
```

### Implementation

- **Module:** `storage/atomic.py`
- **Functions:**
  - `atomic_write_text(path, content)` — for PEM, metadata, text files
  - `atomic_write_bytes(path, content)` — for binary PEM formats
- **Used by:**
  - `storage/filesystem.py:_write()` — writes cert, chain, fullchain, metadata
  - `acme/jws.py:save_account_key()` — writes account key
  - `agent/nodes/csr.py:csr_generator()` — writes domain private key

### Resilience Properties

| Scenario | Before | After |
|----------|--------|-------|
| Crash during write | File truncated/corrupt | Old file intact |
| Power failure | Incomplete write on disk | Atomic rename ensures consistency |
| Concurrent writes | Race conditions | Unique temp names → safe |
| Disk full | Partial write visible | Atomic rename fails → old file untouched |

### Performance

Negligible impact:
- `fsync()` flushes OS buffers → small latency (typically < 10ms)
- For a 4 KB PEM file: ~0.4ms added cost
- ACME network operations dominate (100s of ms), making this cost imperceptible

### Test Coverage

12 unit tests in `tests/test_atomic_writes.py`:
- Atomic writes create files correctly
- Overwrites preserve atomicity
- No orphaned temp files
- Large file handling (10 MB)
- Concurrent writes are thread-safe
- Error handling cleans up temp files

**Result:** ✅ All tests pass with zero regressions.
