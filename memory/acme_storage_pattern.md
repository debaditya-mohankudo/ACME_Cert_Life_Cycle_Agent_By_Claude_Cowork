---
name: acme-storage-pattern
description: Storage layer is abstracted — always use storage/ module, never raw filesystem calls
metadata:
  type: feedback
  domain: acme
  priority: 10
  tags: storage, atomic, filesystem, pattern
---

Never call the filesystem directly for certificate or key writes. Always use `storage/filesystem.py` via the storage node (`agent/nodes/storage.py`).

**Why:** `storage/atomic.py` guarantees atomic writes — partial writes on crash would leave a corrupt cert on disk. This is a hard invariant (#6 in CLAUDE.md).

**How to apply:** If a node needs to persist anything, route through the storage node or call `storage/filesystem.py` directly. Never open cert/key files with raw `open()` outside the storage layer.
