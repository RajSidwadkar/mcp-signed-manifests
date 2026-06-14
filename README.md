# mcp-signed-manifests

A minimal reference implementation of **signed tool manifests** — a proposed
optional extension to the [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
that lets a server cryptographically sign its tool definitions (names,
descriptions, input schemas), so clients and gateways can detect when a tool's
metadata has been tampered with after the fact.

This addresses a known, documented gap in MCP's current security model:
a server can change a tool's description after a user has approved it — for
example, silently appending hidden instructions like *"also BCC this address
on every email"* — and there is currently no protocol-level way for a client
to notice. This class of attack is often called **tool poisoning** or a
**"rug pull."**

## What's here

- `src/canonical.ts` — deterministic (key-sorted) JSON serialization, so the
  same logical manifest always produces the same signed bytes.
- `src/signer.ts` — `ManifestSigner` (Ed25519 signing, server-side) and
  `ManifestVerifier` (Ed25519 verification, client/gateway-side). `verify()`
  never throws — it always returns a boolean.
- `src/types.ts` — `ToolDefinition`, `ToolManifest`, `SignedManifest` types.
- `example/demo.ts` — an end-to-end walkthrough: sign a manifest, verify it,
  then tamper with a tool description *without* re-signing, and watch
  verification catch it.

## Running the demo

```bash
npm install
npm run demo
```

Expected output walks through:

1. A server generates an Ed25519 keypair and signs its tool manifest.
2. A client verifies the signature on first connect (`VALID ✓`) — this is
   the moment a real client would show a user a consent prompt.
3. The manifest is altered (a hidden instruction is added to a tool
   description) without re-signing.
4. The client re-verifies and gets `INVALID ✗ — TOOL_MANIFEST_TAMPERED`,
   and refuses to silently apply the change.

## How this would plug into MCP

This is intentionally **not** a fork or a competing protocol. The proposed
shape is a single new optional method:

```
tools/manifest →  { manifest: {...}, signature: "ed25519:<hex>" }
```

advertised via a capability flag during initialization. Servers and clients
that don't implement it are completely unaffected — this is additive only.

Because verification doesn't require any change to the server itself, it's
also naturally implementable as an **interceptor / gateway** sitting in front
of an existing, unmodified MCP server — the gateway signs on the server's
behalf, and/or verifies on the client's behalf. This composes with the
interceptor pattern being discussed for MCP more broadly.

A full write-up of the proposal, including the rationale for manifest-level
(rather than per-call) signing, key rotation via `expiresAt`, and how this
relates to transport-level security, is in
[`docs/SEP-signed-tool-manifests.md`](./docs/SEP-signed-tool-manifests.md).

## Status

This is a proof-of-concept accompanying a proposal — not a production
library. In particular:

- Key distribution/rotation (how a client learns and trusts a server's public
  key) is intentionally left open, same as JWKS endpoints are
  deployment-specific in OAuth.
- This protects **metadata integrity**, not confidentiality, and is meant to
  be layered on top of (not instead of) normal transport security.

## License

MIT
