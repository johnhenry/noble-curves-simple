import { _validateObject, abool, aInRange, bytesToNumberLE, concatBytes, ensureBytes, numberToBytesLE, randomBytes, type FHash, type Hex } from "../utils.ts";
import type { AffinePoint } from "./curve.ts";
import type { ExtPointConstructor, ExtPointType } from "./edwards.ts";

/**
 * EdDSA (Edwards Digital Signature algorithm) options.
 *
 * * hash: hash function used to hash private keys and messages
 * * adjustScalarBytes: clears bits to get valid field element
 * * domain: Used for hashing
 * * mapToCurve: for hash-to-curve standard
 * * prehash: RFC 8032 pre-hashing of messages to sign() / verify()
 * * randomBytes: function generating random bytes, used for randomPrivateKey
 */
export type EdDSAOpts = {
  hash: FHash;
  adjustScalarBytes?: (bytes: Uint8Array) => Uint8Array;
  domain?: (data: Uint8Array, ctx: Uint8Array, phflag: boolean) => Uint8Array;
  mapToCurve?: (scalar: bigint[]) => AffinePoint<bigint>;
  prehash?: FHash;
  randomBytes?: (bytesLength?: number) => Uint8Array;
};

/**
 * EdDSA (Edwards Digital Signature algorithm) interface.
 *
 * Allows to create and verify signatures, create public and private keys.
 */
export interface EdDSA {
  getPublicKey: (privateKey: Hex) => Uint8Array;
  sign: (message: Hex, privateKey: Hex, options?: { context?: Hex }) => Uint8Array;
  verify: (
    sig: Hex,
    message: Hex,
    publicKey: Hex,
    options?: { context?: Hex; zip215: boolean }
  ) => boolean;
  Point: ExtPointConstructor;
  utils: {
    randomPrivateKey: () => Uint8Array;
    getExtendedPublicKey: (key: Hex) => {
      head: Uint8Array;
      prefix: Uint8Array;
      scalar: bigint;
      point: ExtPointType;
      pointBytes: Uint8Array;
    };
    precompute: (windowSize?: number, point?: ExtPointType) => ExtPointType;
  };
}

const _0n = BigInt(0);

/**
 * Initializes EdDSA signatures over given Edwards curve.
 */
export function eddsa(Point: ExtPointConstructor, eddsaOpts: EdDSAOpts): EdDSA {
  _validateObject(
    eddsaOpts,
    {
      hash: 'function',
    },
    {
      adjustScalarBytes: 'function',
      randomBytes: 'function',
      domain: 'function',
      prehash: 'function',
      mapToCurve: 'function',
    }
  );

  const { prehash, hash: cHash } = eddsaOpts;
  const { BASE: G, Fp, Fn } = Point;
  const CURVE_ORDER = Fn.ORDER;

  const randomBytes_ = eddsaOpts.randomBytes || randomBytes;
  const adjustScalarBytes = eddsaOpts.adjustScalarBytes || ((bytes: Uint8Array) => bytes); // NOOP
  const domain =
    eddsaOpts.domain ||
    ((data: Uint8Array, ctx: Uint8Array, phflag: boolean) => {
      abool('phflag', phflag);
      if (ctx.length || phflag) throw new Error('Contexts/pre-hash are not supported');
      return data;
    }); // NOOP

  function modN(a: bigint) {
    return Fn.create(a);
  }
  // Little-endian SHA512 with modulo n
  function modN_LE(hash: Uint8Array): bigint {
    // Not using Fn.fromBytes: hash can be 2*Fn.BYTES
    return modN(bytesToNumberLE(hash));
  }

  // Get the hashed private scalar per RFC8032 5.1.5
  function getPrivateScalar(key: Hex) {
    const len = Fp.BYTES;
    key = ensureBytes('private key', key, len);
    // Hash private key with curve's hash function to produce uniformingly random input
    // Check byte lengths: ensure(64, h(ensure(32, key)))
    const hashed = ensureBytes('hashed private key', cHash(key), 2 * len);
    const head = adjustScalarBytes(hashed.slice(0, len)); // clear first half bits, produce FE
    const prefix = hashed.slice(len, 2 * len); // second half is called key prefix (5.1.6)
    const scalar = modN_LE(head); // The actual private scalar
    return { head, prefix, scalar };
  }

  // Convenience method that creates public key from scalar. RFC8032 5.1.5
  function getExtendedPublicKey(key: Hex) {
    const { head, prefix, scalar } = getPrivateScalar(key);
    const point = G.multiply(scalar); // Point on Edwards curve aka public key
    const pointBytes = point.toBytes();
    return { head, prefix, scalar, point, pointBytes };
  }

  // Calculates EdDSA pub key. RFC8032 5.1.5. Privkey is hashed. Use first half with 3 bits cleared
  function getPublicKey(privKey: Hex): Uint8Array {
    return getExtendedPublicKey(privKey).pointBytes;
  }

  // int('LE', SHA512(dom2(F, C) || msgs)) mod N
  function hashDomainToScalar(context: Hex = Uint8Array.of(), ...msgs: Uint8Array[]) {
    const msg = concatBytes(...msgs);
    return modN_LE(cHash(domain(msg, ensureBytes('context', context), !!prehash)));
  }

  /** Signs message with privateKey. RFC8032 5.1.6 */
  function sign(msg: Hex, privKey: Hex, options: { context?: Hex } = {}): Uint8Array {
    msg = ensureBytes('message', msg);
    if (prehash) msg = prehash(msg); // for ed25519ph etc.
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(privKey);
    const r = hashDomainToScalar(options.context, prefix, msg); // r = dom2(F, C) || prefix || PH(M)
    const R = G.multiply(r).toBytes(); // R = rG
    const k = hashDomainToScalar(options.context, R, pointBytes, msg); // R || A || PH(M)
    const s = modN(r + k * scalar); // S = (r + k * s) mod L
    aInRange('signature.s', s, _0n, CURVE_ORDER); // 0 <= s < l
    const L = Fp.BYTES;
    const res = concatBytes(R, numberToBytesLE(s, L));
    return ensureBytes('result', res, L * 2); // 64-byte signature
  }

  // verification rule is either zip215 or rfc8032 / nist186-5. Consult fromHex:
  const VERIFY_DEFAULT = { zip215: true };
  const verifyOpts: { context?: Hex; zip215?: boolean } = VERIFY_DEFAULT;

  /**
   * Verifies EdDSA signature against message and public key. RFC8032 5.1.7.
   * An extended group equation is checked.
   */
  function verify(sig: Hex, msg: Hex, publicKey: Hex, options = verifyOpts): boolean {
    const { context, zip215 } = options;
    const len = Fp.BYTES; // Verifies EdDSA signature against message and public key. RFC8032 5.1.7.
    sig = ensureBytes('signature', sig, 2 * len); // An extended group equation is checked.
    msg = ensureBytes('message', msg);
    publicKey = ensureBytes('publicKey', publicKey, len);
    if (zip215 !== undefined) abool('zip215', zip215);
    if (prehash) msg = prehash(msg); // for ed25519ph, etc

    const s = bytesToNumberLE(sig.slice(len, 2 * len));
    let A, R, SB;
    try {
      // zip215=true is good for consensus-critical apps. =false follows RFC8032 / NIST186-5.
      // zip215=true:  0 <= y < MASK (2^256 for ed25519)
      // zip215=false: 0 <= y < P (2^255-19 for ed25519)
      A = Point.fromHex(publicKey, zip215);
      R = Point.fromHex(sig.slice(0, len), zip215);
      SB = G.multiplyUnsafe(s); // 0 <= s < l is done inside
    } catch (error) {
      return false;
    }
    if (!zip215 && A.isSmallOrder()) return false;

    const k = hashDomainToScalar(context, R.toBytes(), A.toBytes(), msg);
    const RkA = R.add(A.multiplyUnsafe(k));
    // Extended group equation
    // [8][S]B = [8]R + [8][k]A'
    return RkA.subtract(SB).clearCofactor().is0();
  }

  G._setWindowSize(8); // Enable precomputes. Slows down first publicKey computation by 20ms.

  const utils = {
    getExtendedPublicKey,
    /** ed25519 priv keys are uniform 32b. No need to check for modulo bias, like in secp256k1. */
    randomPrivateKey: (): Uint8Array => randomBytes_!(Fp.BYTES),

    /**
     * We're doing scalar multiplication (used in getPublicKey etc) with precomputed BASE_POINT
     * values. This slows down first getPublicKey() by milliseconds (see Speed section),
     * but allows to speed-up subsequent getPublicKey() calls up to 20x.
     * @param windowSize 2, 4, 8, 16
     */
    precompute(windowSize = 8, point: ExtPointType = Point.BASE): ExtPointType {
      point._setWindowSize(windowSize);
      point.multiply(BigInt(3));
      return point;
    },
  };

  return { getPublicKey, sign, verify, utils, Point };
}
