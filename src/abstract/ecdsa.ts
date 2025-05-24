// import { hmac } from "@noble/hashes/hmac";
import { _validateObject, abool, aInRange, bitMask, bytesToHex, bytesToNumberBE, concatBytes, createHmacDrbg, ensureBytes, hexToBytes, isBytes, numberToHexUnpadded, randomBytes, type CHash, type Hex, type PrivKey } from "../utils.ts";
import { getMinHashLength, mapHashToField } from "./modular.ts";
import { pointPrefix, type HmacFnSync, type ProjConstructor, type ProjPointType, type WeierstrassExtraOpts } from "./weierstrass.ts";

// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2);

/**
 * Options for ECDSA signatures over a Weierstrass curve.
 */
export type ECDSAOpts = {
  hash: CHash;
  hmac: HmacFnSync;
  randomBytes?: (bytesLength?: number) => Uint8Array;
  lowS?: boolean;
  bits2int?: (bytes: Uint8Array) => bigint;
  bits2int_modN?: (bytes: Uint8Array) => bigint;
};

/** ECDSA is only supported for prime fields, not Fp2 (extension fields). */
export interface ECDSA {
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  getSharedSecret: (privateA: PrivKey, publicB: Hex, isCompressed?: boolean) => Uint8Array;
  sign: (msgHash: Hex, privKey: PrivKey, opts?: SignOpts) => RecoveredSignatureType;
  verify: (signature: Hex | SignatureLike, msgHash: Hex, publicKey: Hex, opts?: VerOpts) => boolean;
  Point: ProjConstructor<bigint>;
  Signature: SignatureConstructor;
  utils: {
    isValidPrivateKey(privateKey: PrivKey): boolean;
    randomPrivateKey: () => Uint8Array;
  };
}

export type Entropy = Hex | boolean;
export type SignOpts = { lowS?: boolean; extraEntropy?: Entropy; prehash?: boolean };
export type VerOpts = {
  lowS?: boolean;
  prehash?: boolean;
  format?: 'compact' | 'der' | 'js' | undefined;
};

export type SignatureConstructor = {
  new (r: bigint, s: bigint): SignatureType;
  fromCompact(hex: Hex): SignatureType;
  fromDER(hex: Hex): SignatureType;
};
export type SignatureLike = { r: bigint; s: bigint };
// Instance
export interface SignatureType {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number;
  addRecoveryBit(recovery: number): RecoveredSignatureType;
  hasHighS(): boolean;
  normalizeS(): SignatureType;
  recoverPublicKey(msgHash: Hex): ProjPointType<bigint>;
  toCompactRawBytes(): Uint8Array;
  toCompactHex(): string;
  toDERRawBytes(isCompressed?: boolean): Uint8Array;
  toDERHex(isCompressed?: boolean): string;
}
export type RecoveredSignatureType = SignatureType & {
  readonly recovery: number;
};

export class DERErr extends Error {
  constructor(m = '') {
    super(m);
  }
}
export type IDER = {
  // asn.1 DER encoding utils
  Err: typeof DERErr;
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag: number, data: string) => string;
    // v - value, l - left bytes (unparsed)
    decode(tag: number, data: Uint8Array): { v: Uint8Array; l: Uint8Array };
  };
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num: bigint): string;
    decode(data: Uint8Array): bigint;
  };
  toSig(hex: string | Uint8Array): { r: bigint; s: bigint };
  hexFromSig(sig: { r: bigint; s: bigint }): string;
};
/**
 * ASN.1 DER encoding utilities. ASN is very complex & fragile. Format:
 *
 *     [0x30 (SEQUENCE), bytelength, 0x02 (INTEGER), intLength, R, 0x02 (INTEGER), intLength, S]
 *
 * Docs: https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/, https://luca.ntop.org/Teaching/Appunti/asn1.html
 */
export const DER: IDER = {
  // asn.1 DER encoding utils
  Err: DERErr,
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag: number, data: string): string => {
      const { Err: E } = DER;
      if (tag < 0 || tag > 256) throw new E('tlv.encode: wrong tag');
      if (data.length & 1) throw new E('tlv.encode: unpadded data');
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if ((len.length / 2) & 0b1000_0000) throw new E('tlv.encode: long form length too big');
      // length of length with long form flag
      const lenLen = dataLen > 127 ? numberToHexUnpadded((len.length / 2) | 0b1000_0000) : '';
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    // v - value, l - left bytes (unparsed)
    decode(tag: number, data: Uint8Array): { v: Uint8Array; l: Uint8Array } {
      const { Err: E } = DER;
      let pos = 0;
      if (tag < 0 || tag > 256) throw new E('tlv.encode: wrong tag');
      if (data.length < 2 || data[pos++] !== tag) throw new E('tlv.decode: wrong tlv');
      const first = data[pos++];
      const isLong = !!(first & 0b1000_0000); // First bit of first length byte is flag for short/long form
      let length = 0;
      if (!isLong) length = first;
      else {
        // Long form: [longFlag(1bit), lengthLength(7bit), length (BE)]
        const lenLen = first & 0b0111_1111;
        if (!lenLen) throw new E('tlv.decode(long): indefinite length not supported');
        if (lenLen > 4) throw new E('tlv.decode(long): byte length is too big'); // this will overflow u32 in js
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen) throw new E('tlv.decode: length bytes not complete');
        if (lengthBytes[0] === 0) throw new E('tlv.decode(long): zero leftmost byte');
        for (const b of lengthBytes) length = (length << 8) | b;
        pos += lenLen;
        if (length < 128) throw new E('tlv.decode(long): not minimal encoding');
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length) throw new E('tlv.decode: wrong value length');
      return { v, l: data.subarray(pos + length) };
    },
  },
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num: bigint): string {
      const { Err: E } = DER;
      if (num < _0n) throw new E('integer: negative integers are not allowed');
      let hex = numberToHexUnpadded(num);
      // Pad with zero byte if negative flag is present
      if (Number.parseInt(hex[0], 16) & 0b1000) hex = '00' + hex;
      if (hex.length & 1) throw new E('unexpected DER parsing assertion: unpadded hex');
      return hex;
    },
    decode(data: Uint8Array): bigint {
      const { Err: E } = DER;
      if (data[0] & 0b1000_0000) throw new E('invalid signature integer: negative');
      if (data[0] === 0x00 && !(data[1] & 0b1000_0000))
        throw new E('invalid signature integer: unnecessary leading zero');
      return bytesToNumberBE(data);
    },
  },
  toSig(hex: string | Uint8Array): { r: bigint; s: bigint } {
    // parse DER signature
    const { Err: E, _int: int, _tlv: tlv } = DER;
    const data = ensureBytes('signature', hex);
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(0x30, data);
    if (seqLeftBytes.length) throw new E('invalid signature: left bytes after parsing');
    const { v: rBytes, l: rLeftBytes } = tlv.decode(0x02, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(0x02, rLeftBytes);
    if (sLeftBytes.length) throw new E('invalid signature: left bytes after parsing');
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig: { r: bigint; s: bigint }): string {
    const { _tlv: tlv, _int: int } = DER;
    const rs = tlv.encode(0x02, int.encode(sig.r));
    const ss = tlv.encode(0x02, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(0x30, seq);
  },
};

function validateSigVerOpts(opts: SignOpts | VerOpts) {
  if (opts.lowS !== undefined) abool('lowS', opts.lowS);
  if (opts.prehash !== undefined) abool('prehash', opts.prehash);
}

export function ecdsa(
  Point: ProjConstructor<bigint>,
  ecdsaOpts: ECDSAOpts,
  curveOpts: WeierstrassExtraOpts<bigint> = {}
): ECDSA {
  _validateObject(
    ecdsaOpts,
    { hash: 'function' },
    {
      hmac: 'function',
      lowS: 'boolean',
      randomBytes: 'function',
      bits2int: 'function',
      bits2int_modN: 'function',
    }
  );

  const randomBytes_ = ecdsaOpts.randomBytes || randomBytes;
  const hmac_: HmacFnSync =
    ecdsaOpts.hmac;
    //|| (((key, ...msgs) => hmac(ecdsaOpts.hash, key, concatBytes(...msgs))) satisfies HmacFnSync);

  const { Fp, Fn } = Point;
  const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn;

  function isBiggerThanHalfOrder(number: bigint) {
    const HALF = CURVE_ORDER >> _1n;
    return number > HALF;
  }

  function normalizeS(s: bigint) {
    return isBiggerThanHalfOrder(s) ? Fn.neg(s) : s;
  }
  function aValidRS(title: string, num: bigint) {
    if (!Fn.isValidNot0(num))
      throw new Error(`invalid signature ${title}: out of range 1..CURVE.n`);
  }

  /**
   * ECDSA signature with its (r, s) properties. Supports DER & compact representations.
   */
  class Signature implements SignatureType {
    readonly r: bigint;
    readonly s: bigint;
    readonly recovery?: number;
    constructor(r: bigint, s: bigint, recovery?: number) {
      aValidRS('r', r); // r in [1..N-1]
      aValidRS('s', s); // s in [1..N-1]
      this.r = r;
      this.s = s;
      if (recovery != null) this.recovery = recovery;
      Object.freeze(this);
    }

    // pair (bytes of r, bytes of s)
    static fromCompact(hex: Hex) {
      const L = Fn.BYTES;
      const b = ensureBytes('compactSignature', hex, L * 2);
      return new Signature(Fn.fromBytes(b.subarray(0, L)), Fn.fromBytes(b.subarray(L, L * 2)));
    }

    // DER encoded ECDSA signature
    // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
    static fromDER(hex: Hex) {
      const { r, s } = DER.toSig(ensureBytes('DER', hex));
      return new Signature(r, s);
    }

    addRecoveryBit(recovery: number): RecoveredSignature {
      return new Signature(this.r, this.s, recovery) as RecoveredSignature;
    }

    // ProjPointType<bigint>
    recoverPublicKey(msgHash: Hex): typeof Point.BASE {
      const FIELD_ORDER = Fp.ORDER;
      const { r, s, recovery: rec } = this;
      if (rec == null || ![0, 1, 2, 3].includes(rec)) throw new Error('recovery id invalid');

      // ECDSA recovery is hard for cofactor > 1 curves.
      // In sign, `r = q.x mod n`, and here we recover q.x from r.
      // While recovering q.x >= n, we need to add r+n for cofactor=1 curves.
      // However, for cofactor>1, r+n may not get q.x:
      // r+n*i would need to be done instead where i is unknown.
      // To easily get i, we either need to:
      // a. increase amount of valid recid values (4, 5...); OR
      // b. prohibit non-prime-order signatures (recid > 1).
      const hasCofactor = CURVE_ORDER * _2n < FIELD_ORDER;
      if (hasCofactor && rec > 1) throw new Error('recovery id is ambiguous for h>1 curve');

      const radj = rec === 2 || rec === 3 ? r + CURVE_ORDER : r;
      if (!Fp.isValid(radj)) throw new Error('recovery id 2 or 3 invalid');
      const x = Fp.toBytes(radj);
      const R = Point.fromHex(concatBytes(pointPrefix((rec & 1) === 0), x));
      const ir = Fn.inv(radj); // r^-1
      const h = bits2int_modN(ensureBytes('msgHash', msgHash)); // Truncate hash
      const u1 = Fn.create(-h * ir); // -hr^-1
      const u2 = Fn.create(s * ir); // sr^-1
      // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1). unsafe is fine: there is no private data.
      const Q = Point.BASE.multiplyUnsafe(u1).add(R.multiplyUnsafe(u2));
      if (Q.is0()) throw new Error('point at infinify');
      Q.assertValidity();
      return Q;
    }

    // Signatures should be low-s, to prevent malleability.
    hasHighS(): boolean {
      return isBiggerThanHalfOrder(this.s);
    }

    normalizeS() {
      return this.hasHighS() ? new Signature(this.r, Fn.neg(this.s), this.recovery) : this;
    }

    // DER-encoded
    toDERRawBytes() {
      return hexToBytes(this.toDERHex());
    }
    toDERHex() {
      return DER.hexFromSig(this);
    }

    // padded bytes of r, then padded bytes of s
    toCompactRawBytes() {
      return concatBytes(Fn.toBytes(this.r), Fn.toBytes(this.s));
    }
    toCompactHex() {
      return bytesToHex(this.toCompactRawBytes());
    }
  }
  type RecoveredSignature = Signature & { recovery: number };

  function normPrivateKeyToScalar(key: PrivKey): bigint {
    const { BYTES: expected } = Fn;
    let num: bigint;
    if (typeof key === 'bigint') {
      num = key;
    } else {
      let bytes = ensureBytes('private key', key);
      try {
        num = Fn.fromBytes(bytes);
      } catch (error) {
        throw new Error(
          `invalid private key: expected ui8a of size ${expected}, got ${typeof key}`
        );
      }
    }
    if (curveOpts.wrapPrivateKey) num = Fn.create(num); // disabled by default, enabled for BLS
    if (!Fn.isValidNot0(num)) throw new Error('invalid private key: out of range [1..N-1]');
    return num;
  }
  const utils = {
    isValidPrivateKey(privateKey: PrivKey) {
      try {
        normPrivateKeyToScalar(privateKey);
        return true;
      } catch (error) {
        return false;
      }
    },

    /**
     * Produces cryptographically secure private key from random of size
     * (groupLen + ceil(groupLen / 2)) with modulo bias being negligible.
     */
    randomPrivateKey: (): Uint8Array => {
      const n = CURVE_ORDER;
      return mapHashToField(randomBytes_(getMinHashLength(n)), n);
    },
  };

  /**
   * Computes public key for a private key. Checks for validity of the private key.
   * @param privateKey private key
   * @param isCompressed whether to return compact (default), or full key
   * @returns Public key, full when isCompressed=false; short when isCompressed=true
   */
  function getPublicKey(privateKey: PrivKey, isCompressed = true): Uint8Array {
    return Point.BASE.multiply(normPrivateKeyToScalar(privateKey)).toBytes(isCompressed);
  }

  /**
   * Quick and dirty check for item being public key. Does not validate hex, or being on-curve.
   */
  function isProbPub(item: Hex | bigint): boolean | undefined {
    if (typeof item === 'bigint') return false;
    if (item instanceof Point) return true;
    const arr = ensureBytes('key', item);
    const length = arr.length;
    const L = Fp.BYTES;
    const LC = L + 1; // e.g. 33 for 32
    const LU = 2 * L + 1; // e.g. 65 for 32
    if (Fn.BYTES === LC) {
      return undefined;
    } else {
      return length === LC || length === LU;
    }
  }

  /**
   * ECDH (Elliptic Curve Diffie Hellman).
   * Computes shared public key from private key and public key.
   * Checks: 1) private key validity 2) shared key is on-curve.
   * Does NOT hash the result.
   * @param privateA private key
   * @param publicB different public key
   * @param isCompressed whether to return compact (default), or full key
   * @returns shared public key
   */
  function getSharedSecret(privateA: PrivKey, publicB: Hex, isCompressed = true): Uint8Array {
    if (isProbPub(privateA) === true) throw new Error('first arg must be private key');
    if (isProbPub(publicB) === false) throw new Error('second arg must be public key');
    const b = Point.fromHex(publicB); // check for being on-curve
    return b.multiply(normPrivateKeyToScalar(privateA)).toBytes(isCompressed);
  }

  // RFC6979: ensure ECDSA msg is X bytes and < N. RFC suggests optional truncating via bits2octets.
  // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which matches bits2int.
  // bits2int can produce res>N, we can do mod(res, N) since the bitLen is the same.
  // int2octets can't be used; pads small msgs with 0: unacceptatble for trunc as per RFC vectors
  const bits2int =
    ecdsaOpts.bits2int ||
    function (bytes: Uint8Array): bigint {
      // Our custom check "just in case", for protection against DoS
      if (bytes.length > 8192) throw new Error('input is too large');
      // For curves with nBitLength % 8 !== 0: bits2octets(bits2octets(m)) !== bits2octets(m)
      // for some cases, since bytes.length * 8 is not actual bitLength.
      const num = bytesToNumberBE(bytes); // check for == u8 done here
      const delta = bytes.length * 8 - fnBits; // truncate to nBitLength leftmost bits
      return delta > 0 ? num >> BigInt(delta) : num;
    };
  const bits2int_modN =
    ecdsaOpts.bits2int_modN ||
    function (bytes: Uint8Array): bigint {
      return Fn.create(bits2int(bytes)); // can't use bytesToNumberBE here
    };
  // NOTE: pads output with zero as per spec
  const ORDER_MASK = bitMask(fnBits);
  /**
   * Converts to bytes. Checks if num in `[0..ORDER_MASK-1]` e.g.: `[0..2^256-1]`.
   */
  function int2octets(num: bigint): Uint8Array {
    // IMPORTANT: the check ensures working for case `Fn.BYTES != Fn.BITS * 8`
    aInRange('num < 2^' + fnBits, num, _0n, ORDER_MASK);
    return Fn.toBytes(num);
  }

  // Steps A, D of RFC6979 3.2
  // Creates RFC6979 seed; converts msg/privKey to numbers.
  // Used only in sign, not in verify.
  // NOTE: we cannot assume here that msgHash has same amount of bytes as curve order,
  // this will be invalid at least for P521. Also it can be bigger for P224 + SHA256
  function prepSig(msgHash: Hex, privateKey: PrivKey, opts = defaultSigOpts) {
    if (['recovered', 'canonical'].some((k) => k in opts))
      throw new Error('sign() legacy options not supported');
    const { hash } = ecdsaOpts;
    let { lowS, prehash, extraEntropy: ent } = opts; // generates low-s sigs by default
    if (lowS == null) lowS = true; // RFC6979 3.2: we skip step A, because we already provide hash
    msgHash = ensureBytes('msgHash', msgHash);
    validateSigVerOpts(opts);
    if (prehash) msgHash = ensureBytes('prehashed msgHash', hash(msgHash));

    // We can't later call bits2octets, since nested bits2int is broken for curves
    // with fnBits % 8 !== 0. Because of that, we unwrap it here as int2octets call.
    // const bits2octets = (bits) => int2octets(bits2int_modN(bits))
    const h1int = bits2int_modN(msgHash);
    const d = normPrivateKeyToScalar(privateKey); // validate private key, convert to bigint
    const seedArgs = [int2octets(d), int2octets(h1int)];
    // extraEntropy. RFC6979 3.6: additional k' (optional).
    if (ent != null && ent !== false) {
      // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
      const e = ent === true ? randomBytes_(Fp.BYTES) : ent; // generate random bytes OR pass as-is
      seedArgs.push(ensureBytes('extraEntropy', e)); // check for being bytes
    }
    const seed = concatBytes(...seedArgs); // Step D of RFC6979 3.2
    const m = h1int; // NOTE: no need to call bits2int second time here, it is inside truncateHash!
    // Converts signature params into point w r/s, checks result for validity.
    // Can use scalar blinding b^-1(bm + bdr) where b ∈ [1,q−1] according to
    // https://tches.iacr.org/index.php/TCHES/article/view/7337/6509. We've decided against it:
    // a) dependency on CSPRNG b) 15% slowdown c) doesn't really help since bigints are not CT
    function k2sig(kBytes: Uint8Array): RecoveredSignature | undefined {
      // RFC 6979 Section 3.2, step 3: k = bits2int(T)
      // Important: all mod() calls here must be done over N
      const k = bits2int(kBytes); // Cannot use fields methods, since it is group element
      if (!Fn.isValidNot0(k)) return; // Valid scalars (including k) must be in 1..N-1
      const ik = Fn.inv(k); // k^-1 mod n
      const q = Point.BASE.multiply(k).toAffine(); // q = Gk
      const r = Fn.create(q.x); // r = q.x mod n
      if (r === _0n) return;
      const s = Fn.create(ik * Fn.create(m + r * d)); // Not using blinding here, see comment above
      if (s === _0n) return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n); // recovery bit (2 or 3, when q.x > n)
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = normalizeS(s); // if lowS was passed, ensure s is always
        recovery ^= 1; // // in the bottom half of N
      }
      return new Signature(r, normS, recovery) as RecoveredSignature; // use normS, not s
    }
    return { seed, k2sig };
  }
  const defaultSigOpts: SignOpts = { lowS: ecdsaOpts.lowS, prehash: false };
  const defaultVerOpts: VerOpts = { lowS: ecdsaOpts.lowS, prehash: false };

  /**
   * Signs message hash with a private key.
   * ```
   * sign(m, d, k) where
   *   (x, y) = G × k
   *   r = x mod n
   *   s = (m + dr)/k mod n
   * ```
   * @param msgHash NOT message. msg needs to be hashed to `msgHash`, or use `prehash`.
   * @param privKey private key
   * @param opts lowS for non-malleable sigs. extraEntropy for mixing randomness into k. prehash will hash first arg.
   * @returns signature with recovery param
   */
  function sign(msgHash: Hex, privKey: PrivKey, opts = defaultSigOpts): RecoveredSignature {
    const { seed, k2sig } = prepSig(msgHash, privKey, opts); // Steps A, D of RFC6979 3.2.
    const drbg = createHmacDrbg<RecoveredSignature>(ecdsaOpts.hash.outputLen, Fn.BYTES, hmac_);
    return drbg(seed, k2sig); // Steps B, C, D, E, F, G
  }

  /**
   * Verifies a signature against message hash and public key.
   * Rejects lowS signatures by default: to override,
   * specify option `{lowS: false}`. Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
   *
   * ```
   * verify(r, s, h, P) where
   *   U1 = hs^-1 mod n
   *   U2 = rs^-1 mod n
   *   R = U1⋅G - U2⋅P
   *   mod(R.x, n) == r
   * ```
   */
  function verify(
    signature: Hex | SignatureLike,
    msgHash: Hex,
    publicKey: Hex,
    opts = defaultVerOpts
  ): boolean {
    const sg = signature;
    msgHash = ensureBytes('msgHash', msgHash);
    publicKey = ensureBytes('publicKey', publicKey);
    const { lowS, prehash, format } = opts;

    // Verify opts, deduce signature format
    validateSigVerOpts(opts);
    if ('strict' in opts) throw new Error('options.strict was renamed to lowS');
    if (format !== undefined && !['compact', 'der', 'js'].includes(format))
      throw new Error('format must be compact or der');
    const isHex = typeof sg === 'string' || isBytes(sg);
    const isObj =
      !isHex &&
      !format &&
      typeof sg === 'object' &&
      sg !== null &&
      typeof sg.r === 'bigint' &&
      typeof sg.s === 'bigint';
    if (!isHex && !isObj)
      throw new Error('invalid signature, expected Uint8Array, hex string or Signature instance');
    let _sig: Signature | undefined = undefined;
    let P: ProjPointType<bigint>;
    try {
      if (isObj) {
        if (format === undefined || format === 'js') {
          _sig = new Signature(sg.r, sg.s);
        } else {
          throw new Error('invalid format');
        }
      }
      if (isHex) {
        // TODO: remove this malleable check
        // Signature can be represented in 2 ways: compact (2*Fn.BYTES) & DER (variable-length).
        // Since DER can also be 2*Fn.BYTES bytes, we check for it first.
        try {
          if (format !== 'compact') _sig = Signature.fromDER(sg);
        } catch (derError) {
          if (!(derError instanceof DER.Err)) throw derError;
        }
        if (!_sig && format !== 'der') _sig = Signature.fromCompact(sg);
      }
      P = Point.fromHex(publicKey);
    } catch (error) {
      return false;
    }
    if (!_sig) return false;
    if (lowS && _sig.hasHighS()) return false;
    // todo: optional.hash => hash
    if (prehash) msgHash = ecdsaOpts.hash(msgHash);
    const { r, s } = _sig;
    const h = bits2int_modN(msgHash); // Cannot use fields methods, since it is group element
    const is = Fn.inv(s); // s^-1
    const u1 = Fn.create(h * is); // u1 = hs^-1 mod n
    const u2 = Fn.create(r * is); // u2 = rs^-1 mod n
    const R = Point.BASE.multiplyUnsafe(u1).add(P.multiplyUnsafe(u2));
    if (R.is0()) return false;
    const v = Fn.create(R.x); // v = r.x mod n
    return v === r;
  }

  // Enable precomputes. Slows down first publicKey computation by 20ms.
  Point.BASE.precompute(8);

  // TODO: clarify API for cloning .clone({hash: sha512}) ? .createWith({hash: sha512})?
  // const clone = (hash: CHash): ECDSA => ecdsa(Point, { ...ecdsaOpts, ...getHash(hash) }, curveOpts);
  return Object.freeze({
    getPublicKey,
    getSharedSecret,
    sign,
    verify,
    Signature,
    utils,
    Point,
  });
}