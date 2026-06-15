# Signed Tool Manifests (Tool Integrity Extension) — Proposal Draft

- **Status:** Draft (pre-SEP — not yet assigned a SEP number)
- **Proposed track:** Extensions Track (per SEP-1724)
- **Created:** 2026-06-14
- **Author:** RajSidwadkar
- **Related work:** SEP-1763 ("Interceptors for Model Context Protocol") — this
  proposal defines a manifest-integrity mechanism that interceptors described
  in SEP-1763 could implement (signing on behalf of unmodified servers,
  verifying on behalf of unmodified clients).

## Abstract

This proposal defines `io.modelcontextprotocol/signed-manifests`, an optional
MCP extension that lets a server cryptographically sign its tool manifest
(names, descriptions, input/output schemas, and annotations) using Ed25519.
Clients, gateways, or interceptors can verify this signature before invoking
any tool and on every manifest refresh, detecting post-approval tampering of
tool metadata — commonly referred to as "tool poisoning" or "rug pull" attacks.

The extension is fully additive. Servers and clients that do not implement it
behave exactly as they do today.

## Motivation

MCP's current security guidance already identifies a known gap: a server's
tool descriptions can change after a client has approved them, and because an
LLM consumes tool descriptions as part of its context, a maliciously altered
description can manipulate model behavior without the user noticing. There is
currently no protocol-level mechanism for a client to detect that a tool's
declared metadata has changed since it was last reviewed, or that the metadata
being shown to the model differs from what was originally vetted.

This affects:

- **Direct tampering** — a compromised or malicious server silently edits a
  tool's `description` or `inputSchema` after initial approval.
- **Supply-chain substitution** — a tool registry, package, or proxy serves a
  modified manifest while presenting the original server identity.
- **Aggregation/bridging** — gateways or bridges that wrap multiple servers
  (a common and growing pattern — see SEP-1763) currently have no standard way
  to prove that the manifest they forward matches what the origin server
  actually declared.

Signing the manifest at its source gives every downstream consumer — clients,
interceptors, gateways — a cheap, protocol-native way to detect tampering
without re-establishing trust in every hop.

## Specification

### 1. Capability advertisement

During initialization / `server/discover` (per the current spec's capability
negotiation), a server that supports this extension advertises:

```json
"capabilities": {
  "io.modelcontextprotocol/signed-manifests": {
    "algorithm": "ed25519",
    "keyId": "uap:issuer:my-server:v1"
  }
}
```

A client that does not recognize this capability ignores it; the server
continues to operate normally.

### 2. Canonical manifest representation

The signed payload is the JSON-serialized array of tool definitions exactly as
returned by `tools/list`, with object keys sorted lexicographically at every
level (canonical JSON), plus an envelope:

```json
{
  "issuer": "my-server",
  "keyId": "uap:issuer:my-server:v1",
  "issuedAt": 1750000000000,
  "expiresAt": 1752592000000,
  "tools": [ /* canonical tool definitions */ ]
}
```

### 3. New method: `tools/manifest`

Servers supporting this extension implement an additional method:

```
Request:  tools/manifest
Response: {
  "manifest": { ...as above... },
  "signature": "ed25519:<hex>"
}
```

The signature is computed over the canonical JSON serialization of
`manifest` using the private key corresponding to `keyId`. Public keys are
resolved out-of-band (e.g., published alongside the server, or via a registry
— left to implementers in v1, analogous to how JWKS resolution is left to
deployment in OAuth).

### 4. Verification behavior

A conforming client, gateway, or interceptor that supports this extension
SHOULD:

1. Call `tools/manifest` once at connection time and verify the signature
   against the advertised `keyId`.
2. Cache the verified manifest hash alongside the user's tool-approval
   decisions.
3. On every subsequent `tools/list` (or notification of tool list change),
   recompute the canonical hash and compare. If it differs from the verified
   manifest **and** the signature over the new manifest does not verify (or
   `expiresAt` has passed), treat this as `TOOL_MANIFEST_TAMPERED`:
   - do not silently re-approve the changed tools,
   - surface the change to the user/operator for re-consent,
   - optionally refuse to invoke the affected tools until re-approved.

Verification failure is a *signal*, not a hard protocol error — implementers
choose the response (warn, block, re-prompt) appropriate to their trust model.

### 5. Interceptor-friendly design

This extension is intentionally separable from any single server
implementation. As proposed in SEP-1763, an **interceptor** can:

- call `tools/manifest` on behalf of a server that doesn't natively support
  signing (acting as a signing bridge for already-deployed MCP servers), or
- verify manifests on behalf of a client that doesn't natively support
  verification.

This means the extension can be adopted incrementally via gateway/sidecar
deployments before any first-party server or client SDK changes, which
matches MCP's existing pattern of optional, composable extensions.

### 6. Manifest Fingerprint (Reference Anchor)

In addition to the Ed25519 signature, implementers MAY compute a
**manifest fingerprint**:

```
manifestHash = "sha256:" + hex(SHA-256(canonical_bytes(manifest)))
```

where `canonical_bytes(manifest)` is the same canonical JSON serialization
defined in Section 2 (sorted keys, no whitespace), applied to the `manifest`
object only (not the envelope's `signature` field).

The fingerprint is a short, lookup-friendly identifier for a specific signed
manifest snapshot. Other extensions — e.g., per-call attestation records or
runtime-enforcement policy compilers — MAY reference `manifestHash` to bind
their own records to the exact manifest version that was active at the time,
without needing to embed or re-transmit the full manifest.

This proposal does not define those consuming extensions. It defines the
canonical form and fingerprint so that any extension wishing to reference a
signed manifest snapshot has a single, unambiguous way to do so.


## Rationale and alternatives considered

- **Per-call signing of tool invocations** was considered and rejected for v1
  — it adds cryptographic overhead to every request for a problem that is
  fundamentally about *metadata* integrity, not per-call authenticity. Manifest
  signing only adds cost at connection time and on manifest refresh.
- **Relying on transport security (TLS/mTLS) alone** does not address this
  threat model: a compromised or malicious server is a trusted TLS endpoint
  that can still serve tampered metadata. Manifest signing addresses
  *content* integrity, which is orthogonal to *transport* integrity.
- **Hashing without signing** (e.g., TOFU-style pinning of a manifest hash)
  is simpler but provides no way to distinguish a legitimate version bump from
  tampering, and no portable notion of issuer identity across deployments.
  Signing with a versioned `keyId` and `expiresAt` allows legitimate rotation.

## Backwards compatibility

Fully additive. No existing field, method, or message is changed. Servers,
clients, and interceptors that do not implement
`io.modelcontextprotocol/signed-manifests` are unaffected.

## Security considerations

- This extension protects manifest **integrity**, not **confidentiality** —
  manifests are not encrypted.
- Key management (rotation, revocation, distribution of public keys) is
  explicitly out of scope for v1 and left to deployment-specific registries or
  bridges, similar to how JWKS endpoints are deployment-specific in OAuth.
- `expiresAt` exists to bound the validity window of a given signature and
  encourage periodic re-signing, reducing the value of a leaked or
  long-unrotated key.
- This extension does not replace transport-level security and is designed to
  be layered with it.

## Reference implementation

A reference implementation (Ed25519 signer/verifier + a runnable demo showing
tamper detection) is available at:
https://github.com/RajSidwadkar/mcp-signed-manifests