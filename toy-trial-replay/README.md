# Toy trial replay

The harness uses the seven generated known-answer fixtures from
`toy-comparison/toy_dlog.py` in its fixed field and interval. A checkpoint
trial is one fixture ID and includes both methods. Taking alternating IDs
from the built-in list assigns four fixtures to shard 0 and three to shard 1.
Both methods must recover the known answer before the fixture is saved.

From the repository root, with Python 3.8+ on Linux, start the two local shards
with the following commands. Use a fresh directory for a new experiment.

```sh
python3 -I -B toy-trial-replay/replay.py run toy-trial-replay/state 0
python3 -I -B toy-trial-replay/replay.py run toy-trial-replay/state 1
```

To resume, run the same command with the same directory and shard ID. The
shard skips saved IDs and starts at the first unfinished fixture. Each save
flushes a temporary file, atomically replaces the shard snapshot, and fsyncs
its directory. An abrupt kill can leave an unused temporary file. Same-shard
writers serialize on a persistent lock file. Keep that file in place while
any writer could be active.

```sh
python3 -I -B toy-trial-replay/replay.py check toy-trial-replay/state/shard-0.json toy-trial-replay/state/shard-1.json
python3 -I -B toy-trial-replay/check.py
```

Pass checkpoint files to `check` in any order, including earlier snapshots or
multiple copies. It counts agreeing records once per ID and rejects conflicts.
Exit 0 means complete. Exit 1 reports missing coverage within the supplied
snapshots. Exit 2 indicates invalid or unreadable input. The SHA-256 digest
covers the explicit replay version, canonical fixtures, group, assignments,
methods, and upstream benchmark source bytes. Use new state after a digest
change. Checkpoints are local progress records and assume trusted local files.

Counts are the benchmark's modular multiplication counts per method, including
its setup and search breakdown. Wall elapsed time in seconds covers each shard
invocation from entry into the shard function, including checkpoint I/O. Peak
RSS in KiB is the Linux process high-water mark from `getrusage(RUSAGE_SELF)`.
The test runner uses fresh subprocesses and measures the interrupted child's
RSS immediately before sending it SIGKILL. Counts apply only to completed toy
trials in this fixed finite field.
