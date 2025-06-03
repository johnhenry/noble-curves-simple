# noble-curves-simple

Pure JavaScript ES modules version of [@noble/curves](https://github.com/paulmillr/noble-curves) - Audited & minimal JS implementation of elliptic curve cryptography.

This is a pre-compiled version of the noble-curves library that:
- ✅ Works directly with npm-based CDNs (unpkg, jsDelivr, esm.sh, etc.)
- ✅ Pure JavaScript with ES modules
- ✅ Includes TypeScript definitions (.d.ts files)
- ✅ No build step required
- ✅ Same API as the original @noble/curves

## Installation

```bash
npm install noble-curves-simple
```

Or use directly from CDN:

```js
import { secp256k1 } from 'https://unpkg.com/noble-curves-simple/secp256k1.js';
import { ed25519 } from 'https://unpkg.com/noble-curves-simple/ed25519.js';
```

## Usage

The API is identical to [@noble/curves](https://github.com/paulmillr/noble-curves). Please refer to the original documentation for detailed usage instructions.

Quick example:

```js
import { secp256k1 } from 'noble-curves-simple/secp256k1';

// Generate private key
const privKey = secp256k1.utils.randomPrivateKey();

// Get public key
const pubKey = secp256k1.getPublicKey(privKey);

// Sign message
const msgHash = new Uint8Array(32); // Your message hash
const signature = secp256k1.sign(msgHash, privKey);

// Verify signature
const isValid = secp256k1.verify(signature, msgHash, pubKey);
```

## Available Curves

All curves from the original library are available:

- **Short Weierstrass**: `secp256k1`, `p256`, `p384`, `p521`
- **Edwards**: `ed25519`, `ed448`
- **BLS**: `bls12-381`
- **Other**: `bn254`, `pasta`, `jubjub`

## Differences from @noble/curves

1. **Pre-compiled**: This package contains JavaScript files instead of TypeScript
2. **ES Modules only**: Uses `"type": "module"` in package.json
3. **No build dependencies**: No TypeScript or build tools required
4. **CDN-friendly**: Works directly with npm-based CDNs

## Original Library

This is a derivative work of [@noble/curves](https://github.com/paulmillr/noble-curves) by Paul Miller.

- 🔒 [**Audited**](https://github.com/paulmillr/noble-curves#security) by independent security firms
- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🏎 Fast: hand-optimized for caveats of JS engines
- 🔍 Reliable: cross-library tests and fuzzing ensure correctness

## Security

Please refer to the [original security documentation](https://github.com/paulmillr/noble-curves#security) and [audits](https://github.com/paulmillr/noble-curves/tree/main/audit).

## License

MIT License - Same as the original noble-curves library.

## Credits

All credit goes to [Paul Miller](https://paulmillr.com) for creating the original noble-curves library.