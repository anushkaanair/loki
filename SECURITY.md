# Security policy

Loki is a **defensive** security tool: it red-teams LLM applications so their owners
can find and fix weaknesses before someone else does. Please use it accordingly.

## Rules of engagement (enforced in code)

Loki refuses to attack anything you have not established you are allowed to attack.

- **Self-built sandbox targets** (`chat`, `agent`, `rag`) are always permitted. They
  run entirely in-process, hold synthetic canaries, and have no real-world effect.
- **Any other target** — including the generic OpenAI-compatible adapter — refuses to
  run unless you pass `--i-am-authorized-to-test-this` or set `authorized: true` in
  the campaign config. This gate lives in `engine/targets/base.py:authorize()` and is
  covered by tests.
- The agent target's tools are sandboxed: `send_email` sends nothing, `delete_records`
  deletes nothing, `read_file` reads an in-memory fake filesystem, and `fetch_url`
  returns only content the campaign itself planted. Every call is logged.

Do not point Loki at a third-party system you do not own or have written permission
to test. Respect rate limits and terms of service.

## Reporting a vulnerability in Loki itself

Loki is a security tool, so bugs in it matter. If you find a vulnerability — for
example a way to make the "sandboxed" tools cause a real side effect, an authorization
gate bypass, or unsafe deserialization of an evidence bundle — please open a
**private** security advisory on the repository rather than a public issue.

The test suite already covers a few classes of self-inflicted bug (`tests/test_phase2.py`):
path traversal via a finding id, unsafe deserialization in the run-log/evidence load
paths, and sandbox escape from the calculator tool. Contributions that extend that
coverage are especially welcome.

## Data handling

- The judge's classifier trains only on public, already-released research datasets.
- Loki never scrapes a live system for training data.
- Evidence bundles contain full attack transcripts. If you run Loki against a real
  application, treat the resulting `artifacts/` directory as sensitive: it is a
  working exploit set for that system.
