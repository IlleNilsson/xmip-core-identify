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

## What both gates read, read once

A technology at this gate and its sibling at the next read the same bytes,
and neither may depend on the other (ADR-0044), so the reading is here and
both call it:

- `api_key` — the name an API key with no id of its own goes by.
- `authorization` — the `Authorization` header: the scheme, Basic's two
  halves, a quoted parameter list (RFC 7235, RFC 7616), a bearer token's
  short form.
- `evidence` — every name a claim carries across the gates, evidence and
  proof, declared once for the gate that writes it and the one that reads it.
- `principal` — user and service principal names, read and compared one way
  (ADR-0054).
- `jwt` — a compact token's parts and claims.
- `kerberos` — the `Negotiate` token to its AP-REQ's ticket: SPNEGO, GSS-API
  or bare, the service, the realm, the sealed cipher.
- `ntlm` — the AUTHENTICATE message and the client's half of its `NTLMv2`
  response.
- `saml` — an assertion's base64 and the principal it names.

`kerberos` and `ntlm` carry a public `fixture` module that builds the bytes a
client makes, for both gates' tests; it verifies nothing.
