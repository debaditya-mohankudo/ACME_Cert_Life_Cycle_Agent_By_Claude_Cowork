# Usage

## Run one renewal cycle immediately

```bash
python main.py --once
```

## Run on a daily schedule

```bash
python main.py --schedule
```

Runs immediately on start, then repeats daily at `SCHEDULE_TIME` (default `06:00` UTC).

## Override domains for a single run

```bash
python main.py --once --domains api.example.com shop.example.com
```

## Enable checkpointing (resume interrupted runs)

```bash
python main.py --once --checkpoint
```

Uses LangGraph's `MemorySaver` to checkpoint state after each node. If a run is interrupted mid-flow (e.g., a network failure during finalization), the graph can resume from the last completed node.
