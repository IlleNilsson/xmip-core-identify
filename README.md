# xmip-core-identify

The first gate: who is claimed. It reads a claim out of an arrival — passed
by the sender, inferred from configuration, or detected in what is there — on
the transport layer and on the Message layer, and hands it on.

Identification proves nothing. Whether the claim holds is the next gate's
question, and the two are kept apart because the estate needs them apart: X12
identifies and never authenticates, and a record that cannot tell a claim from
a proof cannot settle a dispute. It does not know the Party.

ADR-0019 orders the three gates and ADR-0050 makes each technology under this
repository one mechanism at this gate; `architecture.toml` names them.
