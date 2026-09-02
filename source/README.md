# Authority-to-Execution Profile

An internal, synthetic-only reference profile for keeping four statements
separate:

1. a skill or tool advertises a capability;
2. a policy authorizes a specific action;
3. an execution boundary accepts or denies that action; and
4. an execution receipt supports a claim that the action occurred.

The fixture executor issues a cross-profile receipt only after a recognized
test marker directly observes `EXECUTED` or `DENIED_BEFORE_EXECUTION`.
The authorization must also name the declared owned fixture that emitted the
marker and the exact authorization decision; an observation from another
fixture or decision cannot satisfy that authorization.
An execution receipt must bind back to that controlled observation's executor,
timestamp, authorization window, and event digest before it can support an
occurrence claim.
The fixture event is carried in a canonically hashed, local integrity bundle;
rewriting the event invalidates the bundle before the claim can validate.
Denial evidence documents a non-occurrence. It can never be promoted into an
execution claim. The module has no network, filesystem-action, or live-tool
path.

This is not a scanner comparison, an attestation standard, or evidence about a
third-party skill. It is a fail-closed data contract with local controls.

Run controls with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The control run is source-only; Python bytecode caches are not part of the
portable artifact.

## Replay packet

Build and verify the self-contained synthetic packet with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 build_replay_packet.py --output replay-packet.json
PYTHONDONTWRITEBYTECODE=1 python3 verify_replay_packet.py replay-packet.json
```

It exercises one exact-action allow control and two denials: wrong target and
post-approval action mutation. The packet carries source hashes and every
record needed by the offline verifier. It is an owned, networkless fixture
demonstration, not evidence about a live MCP/API integration or an external
identity provider.
