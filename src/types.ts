/**
 * A single tool definition, as it would appear in an MCP `tools/list`
 * response. This is the part of the protocol that is currently NOT
 * integrity-protected — a malicious or compromised server can change
 * `description` or `inputSchema` after a client has already approved the
 * tool ("tool poisoning" / "rug pull").
 */
export interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  readonly outputSchema?: Record<string, unknown>;
}

/**
 * The full set of tools a server exposes, plus issuer/key metadata.
 * This is the object that gets signed.
 */
export interface ToolManifest {
  readonly issuer: string;
  readonly keyId: string;
  readonly issuedAt: number; // Unix ms
  readonly expiresAt: number; // Unix ms
  readonly tools: ToolDefinition[];
}

/**
 * A manifest plus its Ed25519 signature.
 * This is what `tools/manifest` would return under the proposed extension.
 */
export interface SignedManifest {
  readonly manifest: ToolManifest;
  readonly signature: string; // 'ed25519:<hex>'
}
