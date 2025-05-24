/**
 * Short Weierstrass curve methods. The formula is: y² = x³ + ax + b.
 *
 * ### Design rationale for types
 *
 * * Interaction between classes from different curves should fail:
 *   `k256.Point.BASE.add(p256.Point.BASE)`
 * * For this purpose we want to use `instanceof` operator, which is fast and works during runtime
 * * Different calls of `curve()` would return different classes -
 *   `curve(params) !== curve(params)`: if somebody decided to monkey-patch their curve,
 *   it won't affect others
 *
 * TypeScript can't infer types for classes created inside a function. Classes is one instance
 * of nominative types in TypeScript and interfaces only check for shape, so it's hard to create
 * unique type for every function call.
 *
 * We can use generic types via some param, like curve opts, but that would:
 *     1. Enable interaction between `curve(params)` and `curve(params)` (curves of same params)
 *     which is hard to debug.
 *     2. Params can be generic and we can't enforce them to be constant value:
 *     if somebody creates curve from non-constant params,
 *     it would be allowed to interact with other curves with non-constant params
 *
 * @todo https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-7.html#unique-symbol
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  _validateObject,
  abool,
  abytes,
  bytesToHex,
  concatBytes,
  ensureBytes,
  memoized,
  type Hex
} from '../utils.ts';
import {
  _createCurveFields,
  mulEndo,
  negateCt,
  normalizeZ,
  wNAF,
  type AffinePoint,
  type Group,
  type GroupConstructor
} from './curve.ts';
import {
  FpInvertBatch,
  validateField,
  type IField
} from './modular.ts';

export type { AffinePoint };
export type HmacFnSync = (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;
/**
 * When Weierstrass curve has `a=0`, it becomes Koblitz curve.
 * Koblitz curves allow using **efficiently-computable GLV endomorphism ψ**.
 * Endomorphism uses 2x less RAM, speeds up precomputation by 2x and ECDH / key recovery by 20%.
 * For precomputed wNAF it trades off 1/2 init time & 1/3 ram for 20% perf hit.
 *
 * Endomorphism consists of beta, lambda and splitScalar:
 *
 * 1. GLV endomorphism ψ transforms a point: `P = (x, y) ↦ ψ(P) = (β·x mod p, y)`
 * 2. GLV scalar decomposition transforms a scalar: `k ≡ k₁ + k₂·λ (mod n)`
 * 3. Then these are combined: `k·P = k₁·P + k₂·ψ(P)`
 * 4. Two 128-bit point-by-scalar multiplications + one point addition is faster than
 *    one 256-bit multiplication.
 *
 * where
 * * beta: β ∈ Fₚ with β³ = 1, β ≠ 1
 * * lambda: λ ∈ Fₙ with λ³ = 1, λ ≠ 1
 * * splitScalar decomposes k ↦ k₁, k₂, by using reduced basis vectors.
 *   Gauss lattice reduction calculates them from initial basis vectors `(n, 0), (-λ, 0)`
 *
 * Check out `test/misc/endomorphism.js` and
 * [gist](https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066).
 */
export type EndomorphismOpts = {
  beta: bigint;
  splitScalar: (k: bigint) => { k1neg: boolean; k1: bigint; k2neg: boolean; k2: bigint };
};
/** Instance methods for 3D XYZ points. */
export interface ProjPointType<T> extends Group<ProjPointType<T>> {
  /** projective x coordinate. Note: different from .x */
  readonly px: T;
  /** projective y coordinate. Note: different from .y */
  readonly py: T;
  /** projective z coordinate */
  readonly pz: T;
  /** affine x coordinate */
  get x(): T;
  /** affine y coordinate */
  get y(): T;
  assertValidity(): ProjPointType<T>;
  clearCofactor(): ProjPointType<T>;
  is0(): boolean;
  isTorsionFree(): boolean;
  multiplyUnsafe(scalar: bigint): ProjPointType<T>;
  /**
   * Massively speeds up `p.multiply(n)` by using wnaf precompute tables (caching).
   * Table generation takes 30MB of ram and 10ms on high-end CPU, but may take
   * much longer on slow devices.
   * Actual generation will happen on first call of `.multiply()`.
   * By default, BASE point is precomputed.
   * @param windowSize - table window size
   * @param isLazy - (default true) allows to defer generation
   */
  precompute(windowSize: number, isLazy?: boolean): ProjPointType<T>;

  /** Converts 3D XYZ projective point to 2D xy affine coordinates */
  toAffine(invertedZ?: T): AffinePoint<T>;
  /** Encodes point using IEEE P1363 (DER) encoding. First byte is 2/3/4. Default = isCompressed. */
  toBytes(isCompressed?: boolean): Uint8Array;
  toHex(isCompressed?: boolean): string;
}

/** Static methods for 3D XYZ points. */
export interface ProjConstructor<T> extends GroupConstructor<ProjPointType<T>> {
  Fp: IField<T>;
  Fn: IField<bigint>;
  /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
  new (x: T, y: T, z: T): ProjPointType<T>;
  /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
  fromAffine(p: AffinePoint<T>): ProjPointType<T>;
  fromBytes(encodedPoint: Uint8Array): ProjPointType<T>;
  fromHex(hex: Hex): ProjPointType<T>;
  // normalizeZ(points: ProjPointType<T>[]): ProjPointType<T>[];
  // msm(points: ProjPointType<T>[], scalars: bigint[]): ProjPointType<T>;
}

/**
 * Weierstrass curve options.
 *
 * * p: prime characteristic (order) of finite field, in which arithmetics is done
 * * n: order of prime subgroup a.k.a total amount of valid curve points
 * * h: cofactor, usually 1. h*n is group order; n is subgroup order
 * * a: formula param, must be in field of p
 * * b: formula param, must be in field of p
 * * Gx: x coordinate of generator point a.k.a. base point
 * * Gy: y coordinate of generator point
 */
export type WeierstrassOpts<T> = Readonly<{
  p: bigint;
  n: bigint;
  h: bigint;
  a: T;
  b: T;
  Gx: T;
  Gy: T;
}>;

// When a cofactor != 1, there can be an effective methods to:
// 1. Determine whether a point is torsion-free
// 2. Clear torsion component
// wrapPrivateKey: bls12-381 requires mod(n) instead of rejecting keys >= n
export type WeierstrassExtraOpts<T> = Partial<{
  Fp: IField<T>;
  Fn: IField<bigint>;
  allowInfinityPoint: boolean;
  endo: EndomorphismOpts;
  wrapPrivateKey: boolean;
  isTorsionFree: (c: ProjConstructor<T>, point: ProjPointType<T>) => boolean;
  clearCofactor: (c: ProjConstructor<T>, point: ProjPointType<T>) => ProjPointType<T>;
  fromBytes: (bytes: Uint8Array) => AffinePoint<T>;
  toBytes: (c: ProjConstructor<T>, point: ProjPointType<T>, isCompressed: boolean) => Uint8Array;
}>;


// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3), _4n = BigInt(4);

// Points start with byte 0x02 when y is even; otherwise 0x03
export function pointPrefix(hasEvenY: boolean): Uint8Array {
  return Uint8Array.of(hasEvenY ? 0x02 : 0x03);
}

export function weierstrassN<T>(
  CURVE: WeierstrassOpts<T>,
  curveOpts: WeierstrassExtraOpts<T> = {}
): ProjConstructor<T> {
  const { Fp, Fn } = _createCurveFields('weierstrass', CURVE, curveOpts);
  const { h: cofactor, n: CURVE_ORDER } = CURVE;
  _validateObject(
    curveOpts,
    {},
    {
      allowInfinityPoint: 'boolean',
      clearCofactor: 'function',
      isTorsionFree: 'function',
      fromBytes: 'function',
      toBytes: 'function',
      endo: 'object',
      wrapPrivateKey: 'boolean',
    }
  );

  const { endo } = curveOpts;
  if (endo) {
    // validateObject(endo, { beta: 'bigint', splitScalar: 'function' });
    if (
      !Fp.is0(CURVE.a) ||
      typeof endo.beta !== 'bigint' ||
      typeof endo.splitScalar !== 'function'
    ) {
      throw new Error('invalid endo: expected "beta": bigint and "splitScalar": function');
    }
  }

  function assertCompressionIsSupported() {
    if (!Fp.isOdd) throw new Error('compression is not supported: Field does not have .isOdd()');
  }

  // Implements IEEE P1363 point encoding
  function pointToBytes(
    _c: ProjConstructor<T>,
    point: ProjPointType<T>,
    isCompressed: boolean
  ): Uint8Array {
    const { x, y } = point.toAffine();
    const bx = Fp.toBytes(x);
    abool('isCompressed', isCompressed);
    if (isCompressed) {
      assertCompressionIsSupported();
      const hasEvenY = !Fp.isOdd!(y);
      return concatBytes(pointPrefix(hasEvenY), bx);
    } else {
      return concatBytes(Uint8Array.of(0x04), bx, Fp.toBytes(y));
    }
  }
  function pointFromBytes(bytes: Uint8Array) {
    abytes(bytes);
    const L = Fp.BYTES;
    const LC = L + 1; // length compressed, e.g. 33 for 32-byte field
    const LU = 2 * L + 1; // length uncompressed, e.g. 65 for 32-byte field
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    // No actual validation is done here: use .assertValidity()
    if (length === LC && (head === 0x02 || head === 0x03)) {
      const x = Fp.fromBytes(tail);
      // TODO: what about curves with valid point at x=0?
      if (!Fp.isValidNot0(x)) throw new Error('bad point: is not on curve, wrong x');
      const y2 = weierstrassEquation(x); // y² = x³ + ax + b
      let y: T;
      try {
        y = Fp.sqrt(y2); // y = y² ^ (p+1)/4
      } catch (sqrtError) {
        const err = sqrtError instanceof Error ? ': ' + sqrtError.message : '';
        throw new Error('bad point: is not on curve, sqrt error' + err);
      }
      assertCompressionIsSupported();
      const isYOdd = Fp.isOdd!(y); // (y & _1n) === _1n;
      const isHeadOdd = (head & 1) === 1; // ECDSA-specific
      if (isHeadOdd !== isYOdd) y = Fp.neg(y);
      return { x, y };
    } else if (length === LU && head === 0x04) {
      // TODO: more checks
      const x = Fp.fromBytes(tail.subarray(L * 0, L * 1));
      const y = Fp.fromBytes(tail.subarray(L * 1, L * 2));
      if (!isValidXY(x, y)) throw new Error('bad point: is not on curve');
      return { x, y };
    } else {
      throw new Error(
        `bad point: got length ${length}, expected compressed=${LC} or uncompressed=${LU}`
      );
    }
  }

  const toBytes = curveOpts.toBytes || pointToBytes;
  const fromBytes = curveOpts.fromBytes || pointFromBytes;

  function weierstrassEquation(x: T): T {
    const { a, b } = CURVE;
    const x2 = Fp.sqr(x); // x * x
    const x3 = Fp.mul(x2, x); // x² * x
    return Fp.add(Fp.add(x3, Fp.mul(x, a)), b); // x³ + a * x + b
  }

  /** Checks whether equation holds for given x, y: y² == x³ + ax + b */
  function isValidXY(x: T, y: T): boolean {
    const left = Fp.sqr(y); // y²
    const right = weierstrassEquation(x); // x³ + ax + b
    return Fp.eql(left, right);
  }

  // Validate whether the passed curve params are valid.
  // Test 1: equation y² = x³ + ax + b should work for generator point.
  if (!isValidXY(CURVE.Gx, CURVE.Gy)) throw new Error('bad curve params: generator point');

  // Test 2: discriminant Δ part should be non-zero: 4a³ + 27b² != 0.
  // Guarantees curve is genus-1, smooth (non-singular).
  const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n), _4n);
  const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
  if (Fp.is0(Fp.add(_4a3, _27b2))) throw new Error('bad curve params: a or b');

  /** Asserts coordinate is valid: 0 <= n < Fp.ORDER. */
  function acoord(title: string, n: T, banZero = false) {
    if (!Fp.isValid(n) || (banZero && Fp.is0(n))) throw new Error(`bad point coordinate ${title}`);
    return n;
  }

  function aprjpoint(other: unknown) {
    if (!(other instanceof Point)) throw new Error('ProjectivePoint expected');
  }

  // Memoized toAffine / validity check. They are heavy. Points are immutable.

  // Converts Projective point to affine (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  // (X, Y, Z) ∋ (x=X/Z, y=Y/Z)
  const toAffineMemo = memoized((p: Point, iz?: T): AffinePoint<T> => {
    const { px: x, py: y, pz: z } = p;
    // Fast-path for normalized points
    if (Fp.eql(z, Fp.ONE)) return { x, y };
    const is0 = p.is0();
    // If invZ was 0, we return zero point. However we still want to execute
    // all operations, so we replace invZ with a random number, 1.
    if (iz == null) iz = is0 ? Fp.ONE : Fp.inv(z);
    const ax = Fp.mul(x, iz);
    const ay = Fp.mul(y, iz);
    const zz = Fp.mul(z, iz);
    if (is0) return { x: Fp.ZERO, y: Fp.ZERO };
    if (!Fp.eql(zz, Fp.ONE)) throw new Error('invZ was invalid');
    return { x: ax, y: ay };
  });
  // NOTE: on exception this will crash 'cached' and no value will be set.
  // Otherwise true will be return
  const assertValidMemo = memoized((p: Point) => {
    if (p.is0()) {
      // (0, 1, 0) aka ZERO is invalid in most contexts.
      // In BLS, ZERO can be serialized, so we allow it.
      // (0, 0, 0) is invalid representation of ZERO.
      if (curveOpts.allowInfinityPoint && !Fp.is0(p.py)) return;
      throw new Error('bad point: ZERO');
    }
    // Some 3rd-party test vectors require different wording between here & `fromCompressedHex`
    const { x, y } = p.toAffine();
    if (!Fp.isValid(x) || !Fp.isValid(y)) throw new Error('bad point: x or y not field elements');
    if (!isValidXY(x, y)) throw new Error('bad point: equation left != right');
    if (!p.isTorsionFree()) throw new Error('bad point: not in prime-order subgroup');
    return true;
  });

  function finishEndo(
    endoBeta: EndomorphismOpts['beta'],
    k1p: Point,
    k2p: Point,
    k1neg: boolean,
    k2neg: boolean
  ) {
    k2p = new Point(Fp.mul(k2p.px, endoBeta), k2p.py, k2p.pz);
    k1p = negateCt(k1neg, k1p);
    k2p = negateCt(k2neg, k2p);
    return k1p.add(k2p);
  }

  /**
   * Projective Point works in 3d / projective (homogeneous) coordinates:(X, Y, Z) ∋ (x=X/Z, y=Y/Z).
   * Default Point works in 2d / affine coordinates: (x, y).
   * We're doing calculations in projective, because its operations don't require costly inversion.
   */
  class Point implements ProjPointType<T> {
    // base / generator point
    static readonly BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
    // zero / infinity / identity point
    static readonly ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO); // 0, 1, 0
    // fields
    static readonly Fp = Fp;
    static readonly Fn = Fn;

    readonly px: T;
    readonly py: T;
    readonly pz: T;

    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    constructor(px: T, py: T, pz: T) {
      this.px = acoord('x', px);
      this.py = acoord('y', py, true);
      this.pz = acoord('z', pz);
      Object.freeze(this);
    }

    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    static fromAffine(p: AffinePoint<T>): Point {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y)) throw new Error('invalid affine point');
      if (p instanceof Point) throw new Error('projective point not allowed');
      // (0, 0) would've produced (0, 0, 1) - instead, we need (0, 1, 0)
      if (Fp.is0(x) && Fp.is0(y)) return Point.ZERO;
      return new Point(x, y, Fp.ONE);
    }

    get x(): T {
      return this.toAffine().x;
    }
    get y(): T {
      return this.toAffine().y;
    }

    static normalizeZ(points: Point[]): Point[] {
      return normalizeZ(Point, 'pz', points);
    }

    static fromBytes(bytes: Uint8Array): Point {
      abytes(bytes);
      return Point.fromHex(bytes);
    }

    /** Converts hash string or Uint8Array to Point. */
    static fromHex(hex: Hex): Point {
      const P = Point.fromAffine(fromBytes(ensureBytes('pointHex', hex)));
      return P.assertValidity();
    }

    /** Multiscalar Multiplication */
    // static msm(points: Point[], scalars: bigint[]): Point {
    //   return pippenger(Point, Fn, points, scalars);
    // }

    /**
     *
     * @param windowSize
     * @param isLazy true will defer table computation until the first multiplication
     * @returns
     */
    precompute(windowSize: number, isLazy = true): Point {
      wnaf.setWindowSize(this, windowSize);
      if (!isLazy) this.multiply(_3n); // random number
      return this;
    }

    // TODO: return `this`
    /** A point on curve is valid if it conforms to equation. */
    assertValidity(): Point {
      assertValidMemo(this);
      return this;
    }

    hasEvenY(): boolean {
      const { y } = this.toAffine();
      if (!Fp.isOdd) throw new Error("Field doesn't support isOdd");
      return !Fp.isOdd(y);
    }

    /** Compare one point to another. */
    equals(other: Point): boolean {
      aprjpoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }

    /** Flips point to one corresponding to (x, -y) in Affine coordinates. */
    negate(): Point {
      return new Point(this.px, Fp.neg(this.py), this.pz);
    }

    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { a, b } = CURVE;
      const b3 = Fp.mul(b, _3n);
      const { px: X1, py: Y1, pz: Z1 } = this;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
      let t0 = Fp.mul(X1, X1); // step 1
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3); // step 5
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = Fp.mul(a, Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3); // step 10
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3); // step 15
      t2 = Fp.mul(a, t2);
      t3 = Fp.sub(t0, t2);
      t3 = Fp.mul(a, t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0); // step 20
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1); // step 25
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3); // step 30
      Z3 = Fp.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }

    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other: Point): Point {
      aprjpoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
      const a = CURVE.a;
      const b3 = Fp.mul(CURVE.b, _3n);
      let t0 = Fp.mul(X1, X2); // step 1
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2); // step 5
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2); // step 10
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2); // step 15
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = Fp.mul(a, t4);
      X3 = Fp.mul(b3, t2); // step 20
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0); // step 25
      t1 = Fp.add(t1, t0);
      t2 = Fp.mul(a, t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2); // step 30
      t2 = Fp.mul(a, t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4); // step 35
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0); // step 40
      return new Point(X3, Y3, Z3);
    }

    subtract(other: Point) {
      return this.add(other.negate());
    }

    is0(): boolean {
      return this.equals(Point.ZERO);
    }

    /**
     * Constant time multiplication.
     * Uses wNAF method. Windowed method may be 10% faster,
     * but takes 2x longer to generate and consumes 2x memory.
     * Uses precomputes when available.
     * Uses endomorphism for Koblitz curves.
     * @param scalar by which the point would be multiplied
     * @returns New point
     */
    multiply(scalar: bigint): Point {
      const { endo } = curveOpts;
      if (!Fn.isValidNot0(scalar)) throw new Error('invalid scalar: out of range'); // 0 is invalid
      let point: Point, fake: Point; // Fake point is used to const-time mult
      const mul = (n: bigint) => wnaf.cached(this, n, Point.normalizeZ);
      /** See docs for {@link EndomorphismOpts} */
      if (endo) {
        const { k1neg, k1, k2neg, k2 } = endo.splitScalar(scalar);
        const { p: k1p, f: k1f } = mul(k1);
        const { p: k2p, f: k2f } = mul(k2);
        fake = k1f.add(k2f);
        point = finishEndo(endo.beta, k1p, k2p, k1neg, k2neg);
      } else {
        const { p, f } = mul(scalar);
        point = p;
        fake = f;
      }
      // Normalize `z` for both points, but return only real one
      return Point.normalizeZ([point, fake])[0];
    }

    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed private key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(sc: bigint): Point {
      const { endo } = curveOpts;
      const p = this;
      if (!Fn.isValid(sc)) throw new Error('invalid scalar: out of range'); // 0 is valid
      if (sc === _0n || p.is0()) return Point.ZERO;
      if (sc === _1n) return p; // fast-path
      if (wnaf.hasPrecomputes(this)) return this.multiply(sc);
      if (endo) {
        const { k1neg, k1, k2neg, k2 } = endo.splitScalar(sc);
        // `wNAFCachedUnsafe` is 30% slower
        const { p1, p2 } = mulEndo(Point, p, k1, k2);
        return finishEndo(endo.beta, p1, p2, k1neg, k2neg);
      } else {
        return wnaf.unsafe(p, sc);
      }
    }

    multiplyAndAddUnsafe(Q: Point, a: bigint, b: bigint): Point | undefined {
      const sum = this.multiplyUnsafe(a).add(Q.multiplyUnsafe(b));
      return sum.is0() ? undefined : sum;
    }

    /**
     * Converts Projective point to affine (x, y) coordinates.
     * @param invertedZ Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
     */
    toAffine(invertedZ?: T): AffinePoint<T> {
      return toAffineMemo(this, invertedZ);
    }

    /**
     * Checks whether Point is free of torsion elements (is in prime subgroup).
     * Always torsion-free for cofactor=1 curves.
     */
    isTorsionFree(): boolean {
      const { isTorsionFree } = curveOpts;
      if (cofactor === _1n) return true;
      if (isTorsionFree) return isTorsionFree(Point, this);
      return wnaf.unsafe(this, CURVE_ORDER).is0();
    }

    clearCofactor(): Point {
      const { clearCofactor } = curveOpts;
      if (cofactor === _1n) return this; // Fast-path
      if (clearCofactor) return clearCofactor(Point, this) as Point;
      return this.multiplyUnsafe(cofactor);
    }

    toBytes(isCompressed = true): Uint8Array {
      abool('isCompressed', isCompressed);
      return toBytes(Point, this.assertValidity(), isCompressed);
    }

    toHex(isCompressed = true): string {
      abool('isCompressed', isCompressed);
      return bytesToHex(this.toBytes(isCompressed));
    }

    toString() {
      return `<Point ${this.is0() ? 'ZERO' : this.toHex()}>`;
    }
  }
  const bits = Fn.BITS;
  const wnaf = wNAF(Point, curveOpts.endo ? Math.ceil(bits / 2) : bits);
  return Point;
}

/**
 * Implementation of the Shallue and van de Woestijne method for any weierstrass curve.
 * TODO: check if there is a way to merge this with uvRatio in Edwards; move to modular.
 * b = True and y = sqrt(u / v) if (u / v) is square in F, and
 * b = False and y = sqrt(Z * (u / v)) otherwise.
 * @param Fp
 * @param Z
 * @returns
 */
export function SWUFpSqrtRatio<T>(
  Fp: IField<T>,
  Z: T
): (u: T, v: T) => { isValid: boolean; value: T } {
  // Generic implementation
  const q = Fp.ORDER;
  let l = _0n;
  for (let o = q - _1n; o % _2n === _0n; o /= _2n) l += _1n;
  const c1 = l; // 1. c1, the largest integer such that 2^c1 divides q - 1.
  // We need 2n ** c1 and 2n ** (c1-1). We can't use **; but we can use <<.
  // 2n ** c1 == 2n << (c1-1)
  const _2n_pow_c1_1 = _2n << (c1 - _1n - _1n);
  const _2n_pow_c1 = _2n_pow_c1_1 * _2n;
  const c2 = (q - _1n) / _2n_pow_c1; // 2. c2 = (q - 1) / (2^c1)  # Integer arithmetic
  const c3 = (c2 - _1n) / _2n; // 3. c3 = (c2 - 1) / 2            # Integer arithmetic
  const c4 = _2n_pow_c1 - _1n; // 4. c4 = 2^c1 - 1                # Integer arithmetic
  const c5 = _2n_pow_c1_1; // 5. c5 = 2^(c1 - 1)                  # Integer arithmetic
  const c6 = Fp.pow(Z, c2); // 6. c6 = Z^c2
  const c7 = Fp.pow(Z, (c2 + _1n) / _2n); // 7. c7 = Z^((c2 + 1) / 2)
  let sqrtRatio = (u: T, v: T): { isValid: boolean; value: T } => {
    let tv1 = c6; // 1. tv1 = c6
    let tv2 = Fp.pow(v, c4); // 2. tv2 = v^c4
    let tv3 = Fp.sqr(tv2); // 3. tv3 = tv2^2
    tv3 = Fp.mul(tv3, v); // 4. tv3 = tv3 * v
    let tv5 = Fp.mul(u, tv3); // 5. tv5 = u * tv3
    tv5 = Fp.pow(tv5, c3); // 6. tv5 = tv5^c3
    tv5 = Fp.mul(tv5, tv2); // 7. tv5 = tv5 * tv2
    tv2 = Fp.mul(tv5, v); // 8. tv2 = tv5 * v
    tv3 = Fp.mul(tv5, u); // 9. tv3 = tv5 * u
    let tv4 = Fp.mul(tv3, tv2); // 10. tv4 = tv3 * tv2
    tv5 = Fp.pow(tv4, c5); // 11. tv5 = tv4^c5
    let isQR = Fp.eql(tv5, Fp.ONE); // 12. isQR = tv5 == 1
    tv2 = Fp.mul(tv3, c7); // 13. tv2 = tv3 * c7
    tv5 = Fp.mul(tv4, tv1); // 14. tv5 = tv4 * tv1
    tv3 = Fp.cmov(tv2, tv3, isQR); // 15. tv3 = CMOV(tv2, tv3, isQR)
    tv4 = Fp.cmov(tv5, tv4, isQR); // 16. tv4 = CMOV(tv5, tv4, isQR)
    // 17. for i in (c1, c1 - 1, ..., 2):
    for (let i = c1; i > _1n; i--) {
      let tv5 = i - _2n; // 18.    tv5 = i - 2
      tv5 = _2n << (tv5 - _1n); // 19.    tv5 = 2^tv5
      let tvv5 = Fp.pow(tv4, tv5); // 20.    tv5 = tv4^tv5
      const e1 = Fp.eql(tvv5, Fp.ONE); // 21.    e1 = tv5 == 1
      tv2 = Fp.mul(tv3, tv1); // 22.    tv2 = tv3 * tv1
      tv1 = Fp.mul(tv1, tv1); // 23.    tv1 = tv1 * tv1
      tvv5 = Fp.mul(tv4, tv1); // 24.    tv5 = tv4 * tv1
      tv3 = Fp.cmov(tv2, tv3, e1); // 25.    tv3 = CMOV(tv2, tv3, e1)
      tv4 = Fp.cmov(tvv5, tv4, e1); // 26.    tv4 = CMOV(tv5, tv4, e1)
    }
    return { isValid: isQR, value: tv3 };
  };
  if (Fp.ORDER % _4n === _3n) {
    // sqrt_ratio_3mod4(u, v)
    const c1 = (Fp.ORDER - _3n) / _4n; // 1. c1 = (q - 3) / 4     # Integer arithmetic
    const c2 = Fp.sqrt(Fp.neg(Z)); // 2. c2 = sqrt(-Z)
    sqrtRatio = (u: T, v: T) => {
      let tv1 = Fp.sqr(v); // 1. tv1 = v^2
      const tv2 = Fp.mul(u, v); // 2. tv2 = u * v
      tv1 = Fp.mul(tv1, tv2); // 3. tv1 = tv1 * tv2
      let y1 = Fp.pow(tv1, c1); // 4. y1 = tv1^c1
      y1 = Fp.mul(y1, tv2); // 5. y1 = y1 * tv2
      const y2 = Fp.mul(y1, c2); // 6. y2 = y1 * c2
      const tv3 = Fp.mul(Fp.sqr(y1), v); // 7. tv3 = y1^2; 8. tv3 = tv3 * v
      const isQR = Fp.eql(tv3, u); // 9. isQR = tv3 == u
      let y = Fp.cmov(y2, y1, isQR); // 10. y = CMOV(y2, y1, isQR)
      return { isValid: isQR, value: y }; // 11. return (isQR, y) isQR ? y : y*c2
    };
  }
  // No curves uses that
  // if (Fp.ORDER % _8n === _5n) // sqrt_ratio_5mod8
  return sqrtRatio;
}
/**
 * Simplified Shallue-van de Woestijne-Ulas Method
 * https://www.rfc-editor.org/rfc/rfc9380#section-6.6.2
 */
export function mapToCurveSimpleSWU<T>(
  Fp: IField<T>,
  opts: {
    A: T;
    B: T;
    Z: T;
  }
): (u: T) => { x: T; y: T } {
  validateField(Fp);
  const { A, B, Z } = opts;
  if (!Fp.isValid(A) || !Fp.isValid(B) || !Fp.isValid(Z))
    throw new Error('mapToCurveSimpleSWU: invalid opts');
  const sqrtRatio = SWUFpSqrtRatio(Fp, Z);
  if (!Fp.isOdd) throw new Error('Field does not have .isOdd()');
  // Input: u, an element of F.
  // Output: (x, y), a point on E.
  return (u: T): { x: T; y: T } => {
    // prettier-ignore
    let tv1, tv2, tv3, tv4, tv5, tv6, x, y;
    tv1 = Fp.sqr(u); // 1.  tv1 = u^2
    tv1 = Fp.mul(tv1, Z); // 2.  tv1 = Z * tv1
    tv2 = Fp.sqr(tv1); // 3.  tv2 = tv1^2
    tv2 = Fp.add(tv2, tv1); // 4.  tv2 = tv2 + tv1
    tv3 = Fp.add(tv2, Fp.ONE); // 5.  tv3 = tv2 + 1
    tv3 = Fp.mul(tv3, B); // 6.  tv3 = B * tv3
    tv4 = Fp.cmov(Z, Fp.neg(tv2), !Fp.eql(tv2, Fp.ZERO)); // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
    tv4 = Fp.mul(tv4, A); // 8.  tv4 = A * tv4
    tv2 = Fp.sqr(tv3); // 9.  tv2 = tv3^2
    tv6 = Fp.sqr(tv4); // 10. tv6 = tv4^2
    tv5 = Fp.mul(tv6, A); // 11. tv5 = A * tv6
    tv2 = Fp.add(tv2, tv5); // 12. tv2 = tv2 + tv5
    tv2 = Fp.mul(tv2, tv3); // 13. tv2 = tv2 * tv3
    tv6 = Fp.mul(tv6, tv4); // 14. tv6 = tv6 * tv4
    tv5 = Fp.mul(tv6, B); // 15. tv5 = B * tv6
    tv2 = Fp.add(tv2, tv5); // 16. tv2 = tv2 + tv5
    x = Fp.mul(tv1, tv3); // 17.   x = tv1 * tv3
    const { isValid, value } = sqrtRatio(tv2, tv6); // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
    y = Fp.mul(tv1, u); // 19.   y = tv1 * u  -> Z * u^3 * y1
    y = Fp.mul(y, value); // 20.   y = y * y1
    x = Fp.cmov(x, tv3, isValid); // 21.   x = CMOV(x, tv3, is_gx1_square)
    y = Fp.cmov(y, value, isValid); // 22.   y = CMOV(y, y1, is_gx1_square)
    const e1 = Fp.isOdd!(u) === Fp.isOdd!(y); // 23.  e1 = sgn0(u) == sgn0(y)
    y = Fp.cmov(Fp.neg(y), y, e1); // 24.   y = CMOV(-y, y, e1)
    const tv4_inv = FpInvertBatch(Fp, [tv4], true)[0];
    x = Fp.mul(x, tv4_inv); // 25.   x = x / tv4
    return { x, y };
  };
}
