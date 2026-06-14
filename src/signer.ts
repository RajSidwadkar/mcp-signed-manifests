import { ed25519 } from '@noble/curves/ed25519';
import { canonicalJSON } from './canonical';
import type { SignedManifest, ToolManifest } from './types';

const PREFIX = 'ed25519:';

/**
 * Signs tool manifests with an Ed25519 key.
 *
 * In a real deployment, this lives on (or alongside) the MCP server.
 * The private key never leaves the issuer.
 */
export class ManifestSigner {
  private readonly privKey: Uint8Array;
  private readonly pubKey: Uint8Array;

  constructor(privateKeyHex: string) {
    this.privKey = Buffer.from(privateKeyHex.trim(), 'hex');
    this.pubKey = ed25519.getPublicKey(this.privKey);
  }

  /** Generates a fresh keypair. Convenience for demos / dev setup. */
  static generate(): { privateKeyHex: string; publicKeyHex: string } {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    return {
      privateKeyHex: Buffer.from(priv).toString('hex'),
      publicKeyHex: Buffer.from(pub).toString('hex'),
    };
  }

  getPublicKeyHex(): string {
    return Buffer.from(this.pubKey).toString('hex');
  }

  /** Signs a manifest, returning the manifest + signature pair. */
  sign(manifest: ToolManifest): SignedManifest {
    const payload = Buffer.from(canonicalJSON(manifest));
    const sig = ed25519.sign(payload, this.privKey);
    return {
      manifest,
      signature: `${PREFIX}${Buffer.from(sig).toString('hex')}`,
    };
  }
}

/**
 * Verifies signed manifests against a known public key.
 *
 * In a real deployment, this lives on the client / gateway / interceptor
 * side. It never needs the private key.
 *
 * verify() NEVER throws — it always returns a boolean, so callers can use
 * it directly in a conditional without try/catch.
 */
export class ManifestVerifier {
  constructor(private readonly publicKeyHex: string) {}

  verify(signed: SignedManifest): boolean {
    const { manifest, signature } = signed;

    if (!signature || !signature.startsWith(PREFIX)) {
      return false;
    }

    try {
      const sig = Buffer.from(signature.slice(PREFIX.length), 'hex');
      const payload = Buffer.from(canonicalJSON(manifest));
      const pub = Buffer.from(this.publicKeyHex, 'hex');
      return ed25519.verify(sig, payload, pub);
    } catch {
      // Malformed hex, wrong-length key, etc. — treat as "not verified",
      // never crash the caller.
      return false;
    }
  }

  /** Convenience: checks signature validity AND expiry in one call. */
  verifyAndCheckExpiry(signed: SignedManifest, now: number = Date.now()): {
    valid: boolean;
    expired: boolean;
  } {
    const valid = this.verify(signed);
    const expired = signed.manifest.expiresAt < now;
    return { valid, expired };
  }
}
