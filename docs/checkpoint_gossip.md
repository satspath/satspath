# Checkpoint gossip and split-view evidence (experimental)

Issue #96 adds independent checkpoint exchange to `satspath-witness`. The gossip
monitor is a separate executable: it is not automatically enabled by `satspathd`
and does not change resolution or payment routing policy. Clients and witness
operators can independently verify/pin checkpoints, exchange observations, and
persist attributable evidence if the **same operator** signs distinct Merkle roots
for the same `(log_id, tree_size)`.

## Protocol

An observation contains the full `TransparencyCheckpoint` (including its operator
signature), a compressed observer public key, `observed_at`, version 1, and a
BIP-340 signature over domain-separated canonical JSON
(`SatsPathCheckpointGossipV1`). A digest/root signed only by an observer is **not**
evidence of operator misconduct. The monitor checks both signatures, the exact
out-of-band `log_id` and operator key, and a configured list of authorized
observer keys before accepting relay input. A relay cannot define trust anchors.

Observations travel in NIP-01 events signed by the *same* observer key. Experimental
regular kind `3978` is retained by relays; the `d` tag is
`SHA256("SatsPathCheckpointGossipTopicV1:" || UTF8(log_id))`. Subscriptions filter
on kind, `#d` and authorized Nostr x-only authors. The receiver recomputes the
event ID and validates the Nostr Schnorr signature, tag, author/content binding,
observer signature, operator signature and checkpoint scope. At most 64 KiB of
observation JSON and about 130 KiB of relay framing are accepted. Ingest limits
the observation timestamp and Nostr event timestamp to seven days old and five
minutes in the future; already stored signed evidence remains verifiable later.

Different tree sizes are **inconclusive**, not evidence of a fork without a
checkpoint-bound consistency proof. For equal sizes, distinct log or state-map roots from two
different authorized observers yield `SplitViewEvidence` containing both full
signed checkpoints. An identical root is consistent even if an optional Bitcoin
receipt changed its checkpoint signature. The first verified local checkpoint
and later observed advancements are checked by the existing `WitnessService` and
its RFC 6962 consistency proof logic before being announced. The monitor stores
observations and deduplicated alerts under the state directory and prints newly
detected alerts with the `GOSSIP_SPLIT_VIEW` prefix to stderr. `alerts` re-verifies
the evidence from disk and prints it as JSON. Storage is bounded to 512 records
and 512 alerts per log (an exhausted store fails rather than silently forgetting
old evidence). Run one monitor per state directory.

## Running two independent observers

Build with `cargo build -p satspath-witness --bin satspath-gossip`. For **each**
observer, create a dedicated key in a private location:

```sh
satspath-gossip keygen --key-file /path/to/observer.key
```

The printed compressed public key is shared *out of band*. Configure at least
two distinct authorized observer keys and the same trusted log ID and operator
public key on both hosts. The operator key must come from a trusted namespace
descriptor or prior independently authenticated pin, **not** from an untrusted
relay or the checkpoint being inspected.

Independently fetch each node's signed checkpoint from its authority view, and
verify it before publishing (repeat `--observer-pubkey` for every allowed key):

```sh
satspath-gossip observe --state-dir /path/to/state --log-id LOG_ID \
  --operator-pubkey OPERATOR_PUBKEY --observer-pubkey OBSERVER_A \
  --observer-pubkey OBSERVER_B --key-file /path/to/observer.key \
  --checkpoint-file /path/to/checkpoint.json
```

When observing a larger tree after a previous pin, add
`--consistency-file /path/to/consistency-proof.json`. Missing or invalid proof
blocks the update. `observe` does not contact a relay. Then run one monitor on
each host (multiple `--relay` flags enable relay diversity):

```sh
satspath-gossip run --state-dir /path/to/state --log-id LOG_ID \
  --operator-pubkey OPERATOR_PUBKEY --observer-pubkey OBSERVER_A \
  --observer-pubkey OBSERVER_B --key-file /path/to/observer.key \
  --relay wss://relay-one.example --relay wss://relay-two.example

satspath-gossip alerts --state-dir /path/to/state --log-id LOG_ID \
  --operator-pubkey OPERATOR_PUBKEY --observer-pubkey OBSERVER_A \
  --observer-pubkey OBSERVER_B
```

`run` republishes the latest locally verified checkpoint every 15 seconds,
subscribes to up to eight explicit relays and reconnects after disconnection.
Only `wss://` public relay URLs are accepted, except loopback `ws://` with
`--allow-local-ws` for local development. No wallet, spending key or local
profile is transmitted. The observer key must be kept private; `keygen` creates
it with owner-only permissions on Unix. A live network test should use two
different source views and observers before assuming a deployment can detect
split views.

## Threat model and limitations

| Threat | Check / remaining limitation |
| --- | --- |
| Sybil or relay-injected observer keys | Only explicitly configured observer keys count; an alert requires *different x-only identities* (negating a compressed key does not create a second observer) and two valid signatures by the same pinned operator key. A single allowed malicious observer still cannot forge the operator's checkpoint signature. |
| Relay tampering or replay | Validate NIP-01 event ID/signature and both inner signatures; bound message sizes and freshness; deduplicate alerts. Old signed checkpoints remain valid historical evidence. |
| Relay censorship or eclipsing | Publish and subscribe through independent relays. A disconnected/eclipsed verifier can miss the split; no relay or polling scheme guarantees delivery. |
| Different-sized checkpoints | Treated as inconclusive without a consistency proof; this detector currently reports only same-size conflicting roots. Existing local pinning still requires consistency on advancement. |
| First-contact operator substitution | Gossip cannot authenticate the initial namespace/operator-key binding. Operators/clients must establish and pin it independently. |
| Operator key rotation | This version requires one explicitly pinned operator key per monitor configuration. Stop and verify a dual-signed authorized rotation out of band before updating it; do not automatically accept a new key from gossip. |
| Public metadata | The hashed relay topic is dictionary-searchable; checkpoint size, root, operator key, observer key and timestamps are public. It does not grant anonymity. |

Tests cover signature tampering, trust scope, historical evidence verification,
same-root/different-size comparisons, and two independent observers exchanging
conflicting checkpoints over an in-process mock Nostr relay, with restart and
on-disk alert re-verification.
