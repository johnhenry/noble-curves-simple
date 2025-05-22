// Proper modulo function for BigInt (handles negative numbers correctly)
function mod(a, b) {
  const result = a % b;
  return result >= 0n ? result : b + result;
}

// mod-div a bigint num over den, to nearest integer
/**
 *
 * @param {BigInt} num
 * @param {BigInt} den
 * @returns
 */
function divNearest(num, den) {
  if (num >= 0n) {
    return (num + den / 2n) / den;
  } else {
    return (num - den / 2n) / den;
  }
}

/**
 * Apply Gauss lattice reduction to find a reduced basis for a 2D lattice.
 * This is similar to the Euclidean algorithm but for 2D vectors.
 *
 * @param {[BigInt, BigInt]} u - First basis vector
 * @param {[BigInt, BigInt]} v - Second basis vector
 * @returns {[[BigInt, BigInt], [BigInt, BigInt]]} - Reduced basis vectors
 */
function gaussLatticeReduction(u, v) {
  u = [u[0], u[1]]; v = [v[0], v[1]]; // copy
  while (true) {
    // Ensure |u| <= |v|, swap if necessary
    const uNormSquared = u[0] * u[0] + u[1] * u[1];
    const vNormSquared = v[0] * v[0] + v[1] * v[1];
    if (uNormSquared > vNormSquared) [u, v] = [v, u];
    const dot = u[0] * v[0] + u[1] * v[1]; // dot product u·v
    const uNormSquared2 = u[0] * u[0] + u[1] * u[1]; // |u|^2
    // If vectors are nearly orthogonal, we're done
    // 2|u·v| <= |u|^2 means: 60° < angle_between_u_and_v < 120°
    if (2n * (dot < 0n ? -dot : dot) <= uNormSquared2) break;
    const m = divNearest(dot, uNormSquared2); // m = round(u·v / |u|^2)
    v[0] = v[0] - m * u[0]; // Update v = v - m*u
    v[1] = v[1] - m * u[1];
  }
  return [u, v];
}

/**
 * Gaussian Lattice Reduction for 2D lattice basis vectors using BigInt arithmetic
 * Reduces a basis {u, v} to find a shorter, more orthogonal basis
 * Uses BigInt for exact integer arithmetic, crucial for cryptographic applications
 */

class Vector2D {
  constructor(x, y) {
    this.x = BigInt(x);
    this.y = BigInt(y);
  }

  // Dot product
  dot(other) {
    return this.x * other.x + this.y * other.y;
  }

  // Squared length (norm squared)
  normSquared() {
    return this.x * this.x + this.y * this.y;
  }

  // Length (norm) - returns BigInt approximation
  norm() {
    return this.bigIntSqrt(this.normSquared());
  }

  // Subtract another vector
  subtract(other) {
    return new Vector2D(this.x - other.x, this.y - other.y);
  }

  // Add another vector
  add(other) {
    return new Vector2D(this.x + other.x, this.y + other.y);
  }

  // Scalar multiplication
  multiply(scalar) {
    const bigScalar = BigInt(scalar);
    return new Vector2D(this.x * bigScalar, this.y * bigScalar);
  }

  // Copy vector
  copy() {
    return new Vector2D(this.x, this.y);
  }

  // BigInt square root approximation using Newton's method
  bigIntSqrt(value) {
    if (value < 0n) throw new Error("Cannot compute square root of negative number");
    if (value === 0n) return 0n;
    if (value === 1n) return 1n;

    let x = value;
    let y = (x + 1n) / 2n;

    while (y < x) {
      x = y;
      y = (x + value / x) / 2n;
    }

    return x;
  }

  toString() {
    return `(${this.x.toString()}, ${this.y.toString()})`;
  }

  // Convert to regular numbers for display (with potential precision loss warning)
  toNumber() {
    const xNum = Number(this.x);
    const yNum = Number(this.y);

    // Check for precision loss
    if (this.x > Number.MAX_SAFE_INTEGER || this.y > Number.MAX_SAFE_INTEGER ||
      this.x < Number.MIN_SAFE_INTEGER || this.y < Number.MIN_SAFE_INTEGER) {
      console.warn("Warning: Precision loss when converting BigInt to Number");
    }

    return { x: xNum, y: yNum };
  }
}

/**
 * Extended Euclidean Algorithm for BigInt
 * Returns { gcd, x, y } such that ax + by = gcd(a, b)
 */
function extendedGcdBigInt(a, b) {
  if (b === 0n) {
    return { gcd: a, x: 1n, y: 0n };
  }

  const result = extendedGcdBigInt(b, a % b);
  return {
    gcd: result.gcd,
    x: result.y,
    y: result.x - (a / b) * result.y
  };
}

/**
 * Round division for BigInt (rounds to nearest integer)
 * Computes round(numerator / denominator)
 * @param {BigInt} numerator
 * @param {BigInt} denominator
 */
function roundDivisionBigInt(numerator, denominator) {
  if (denominator === 0n) throw new Error("Division by zero");

  const quotient = numerator / denominator;
  const remainder = numerator % denominator;
  const halfDenominator = denominator / 2n;

  // Handle negative numbers correctly
  if (denominator > 0n) {
    if (remainder > halfDenominator || (remainder === halfDenominator && quotient % 2n !== 0n)) {
      return quotient + 1n;
    } else if (remainder < -halfDenominator || (remainder === -halfDenominator && quotient % 2n !== 0n)) {
      return quotient - 1n;
    }
  } else {
    if (remainder < halfDenominator || (remainder === halfDenominator && quotient % 2n !== 0n)) {
      return quotient + 1n;
    } else if (remainder > -halfDenominator || (remainder === -halfDenominator && quotient % 2n !== 0n)) {
      return quotient - 1n;
    }
  }

  return quotient;
}

/**
 * Gaussian Lattice Reduction Algorithm using BigInt
 * @param {Vector2D} u - First basis vector
 * @param {Vector2D} v - Second basis vector
 * @returns {Object} - Object containing reduced basis vectors and transformation matrix
 */
function gaussLatticeReduction_new(u, v) {
  // Work with copies to avoid modifying original vectors
  let u1 = u.copy();
  let v1 = v.copy();

  // Keep track of the transformation matrix (BigInt)
  let transformMatrix = {
    a: 1n, b: 0n,  // coefficients for u1 in terms of original basis
    c: 0n, d: 1n   // coefficients for v1 in terms of original basis
  };

  const steps = [];
  let iteration = 0;

  while (true) {
    iteration++;

    // Step 1: Ensure |u1|² <= |v1|²
    if (u1.normSquared() > v1.normSquared()) {
      // Swap u1 and v1
      [u1, v1] = [v1, u1];
      // Update transformation matrix
      [transformMatrix.a, transformMatrix.c] = [transformMatrix.c, transformMatrix.a];
      [transformMatrix.b, transformMatrix.d] = [transformMatrix.d, transformMatrix.b];

      steps.push({
        step: `Iteration ${iteration}: Swap vectors`,
        u: u1.copy(),
        v: v1.copy(),
        reason: "Ensuring |u|² <= |v|²"
      });
    }

    // Step 2: Compute the Gram coefficient using rounded division
    const numerator = v1.dot(u1);
    const denominator = u1.normSquared();

    if (denominator === 0n) {
      throw new Error("Zero vector encountered in basis");
    }

    const mu = roundDivisionBigInt(numerator, denominator);

    if (mu === 0n) {
      // Basis is already reduced
      steps.push({
        step: `Iteration ${iteration}: Complete`,
        u: u1.copy(),
        v: v1.copy(),
        reason: "μ = 0, basis is reduced"
      });
      break;
    }

    // Step 3: Reduce v1 by subtracting μ * u1
    const oldV1 = v1.copy();
    v1 = v1.subtract(u1.multiply(mu));

    // Update transformation matrix
    transformMatrix.c -= mu * transformMatrix.a;
    transformMatrix.d -= mu * transformMatrix.b;

    steps.push({
      step: `Iteration ${iteration}: Reduce v`,
      u: u1.copy(),
      v: v1.copy(),
      mu: mu,
      oldV: oldV1,
      reason: `v := v - ${mu.toString()} * u`
    });

    // Check for infinite loop protection
    if (iteration > 1000) {
      console.warn("Maximum iterations reached, stopping reduction");
      break;
    }
  }

  return {
    reducedBasis: { u: u1, v: v1 },
    originalBasis: { u: u, v: v },
    transformationMatrix: transformMatrix,
    steps: steps,
    iterations: iteration
  };
}

/**
 * Verify that the reduced basis generates the same lattice
 * @param {Object} result - Result from gaussianLatticeReductionBigInt
 * @returns {boolean} - True if verification passes
 */
function verifyReduction(result) {
  const { originalBasis, reducedBasis, transformationMatrix } = result;
  const { a, b, c, d } = transformationMatrix;

  // Check that the transformation matrix has determinant ±1
  const det = a * d - b * c;
  if (det !== 1n && det !== -1n) {
    console.error("Transformation matrix determinant is not ±1:", det.toString());
    return false;
  }

  // Check that reduced basis vectors can be expressed in terms of original basis
  const u_check = originalBasis.u.multiply(a).add(originalBasis.v.multiply(b));
  const v_check = originalBasis.u.multiply(c).add(originalBasis.v.multiply(d));

  if (u_check.x !== reducedBasis.u.x || u_check.y !== reducedBasis.u.y ||
    v_check.x !== reducedBasis.v.x || v_check.y !== reducedBasis.v.y) {
    console.error("Transformation verification failed");
    console.error("Expected u:", reducedBasis.u.toString());
    console.error("Got u:", u_check.toString());
    console.error("Expected v:", reducedBasis.v.toString());
    console.error("Got v:", v_check.toString());
    return false;
  }

  return true;
}

/**
 * Calculate lattice properties using BigInt
 * @param {Vector2D} u - First basis vector
 * @param {Vector2D} v - Second basis vector
 * @returns {Object} - Lattice properties
 */
function calcLatticeProps(u, v) {
  // Area (determinant) - exact for BigInt
  const area = u.x * v.y - u.y * v.x;
  const absoluteArea = area < 0n ? -area : area;

  // For angles and orthogonality, we'll provide BigInt and approximate Number versions
  const dotProduct = u.dot(v);
  const uNormSq = u.normSquared();
  const vNormSq = v.normSquared();

  return {
    area: absoluteArea,
    areaNumber: Number(absoluteArea), // For display
    dotProduct: dotProduct,
    uNormSquared: uNormSq,
    vNormSquared: vNormSq,
    // Approximate values for display
    uLength: Number(u.norm()),
    vLength: Number(v.norm()),
    // Note: For exact orthogonality, compare dotProduct to 0n
    isOrthogonal: dotProduct === 0n
  };
}

/**
 * Generate a random lattice basis for testing
 * @param {number} maxValue - Maximum absolute value for coordinates
 * @returns {Object} - Object with two random basis vectors
 */
function generateRandomBasis(maxValue = 1000) {
  const randomBigInt = (max) => {
    const sign = Math.random() < 0.5 ? -1n : 1n;
    const value = BigInt(Math.floor(Math.random() * max) + 1);
    return sign * value;
  };

  return {
    u: new Vector2D(randomBigInt(maxValue), randomBigInt(maxValue)),
    v: new Vector2D(randomBigInt(maxValue), randomBigInt(maxValue))
  };
}

// Example usage and demonstration
function demonstrateGaussianReduction() {
  console.log("=== Gaussian Lattice Reduction with BigInt Demo ===\n");
  // Example 3: Cryptographic-sized integers
  const u3 = new Vector2D("115792089237316195423570985008687907852837564279074904382605163141518161494337", "0");
  const v3 = new Vector2D("37718080363155996902926221483475020450927657555482586988616620542887997980019", "1");

  console.log("Example 3 (Cryptographic-sized):");
  console.log(`Original basis: u = ${u3}, v = ${v3}`);

  const result3 = gaussLatticeReduction_new(u3, v3);

  console.log(`Reduced basis: u = ${result3.reducedBasis.u}, v = ${result3.reducedBasis.v}`);
  console.log(`Iterations: ${result3.iterations}`);
  console.log(`Verification: ${verifyReduction(result3) ? "PASS" : "FAIL"}\n`);

  // Compare properties
  const props1 = calcLatticeProps(u3, v3);
  const reducedProps1 = calcLatticeProps(result3.reducedBasis.u, result3.reducedBasis.v);

  console.log("Property comparison (Example 1):");
  console.log(`Original - Area: ${props1.area}, Is Orthogonal: ${props1.isOrthogonal}`);
  console.log(`Reduced  - Area: ${reducedProps1.area}, Is Orthogonal: ${reducedProps1.isOrthogonal}`);

  return { result3 };
}

// Test with random large integers
function testRandomLargeBases(count = 5) {
  console.log("\n=== Testing with Random Large Bases ===");

  for (let i = 0; i < count; i++) {
    const { u, v } = generateRandomBasis(10000);
    console.log(`\nTest ${i + 1}:`);
    console.log(`Basis: u = ${u}, v = ${v}`);

    const result = gaussLatticeReduction_new(u, v);
    const verified = verifyReduction(result);

    console.log(`Reduced: u = ${result.reducedBasis.u}, v = ${result.reducedBasis.v}`);
    console.log(`Iterations: ${result.iterations}, Verified: ${verified ? "PASS" : "FAIL"}`);
  }
}

// Run demonstration if script is executed directly
// demonstrateGaussianReductionBigInt();
// testRandomLargeBases(3);

/**
 * Calculate a reduced basis for the GLV endomorphism on secp256k1.
 *
 * @param {BigInt} n - The order of the curve
 * @param {BigInt} lambda - The endomorphism value lambda
 * @returns {[[BigInt, BigInt], [BigInt, BigInt]]} - Reduced basis vectors
 */
function calculateGlvBasis(n, lambda) {
  // console.log({n, lambda})
  // Initial basis vectors for the lattice L:
  // v1 = (n, 0): This is valid because n ≡ 0 (mod n), so n + 0*lambda ≡ 0 (mod n)
  // v2 = (-lambda, 1): This is valid because -lambda + 1*lambda ≡ 0 (mod n)
  // const v1 = [n, 0n];
  // const v2 = [mod(-lambda, n), 1n];
  const v1 = new Vector2D(n, 0n);
  const v2 = new Vector2D(mod(-lambda, n), 1n);
  // console.log({
  //   v1, v2
  // })
  // Apply Gauss lattice reduction to find a reduced basis
  // gauss lattice reduction of initial basis vectors `(n, 0), -(λ, 0)`
  function mapToArr(res) {
    // console.log(res.reducedBasis);
    const item = res.reducedBasis;
    return [[item.u.x, item.u.y], [item.v.x, item.v.y]];
  }
  return mapToArr(gaussLatticeReduction_new(v1, v2));
}

/**
 * Decompose scalar k into k1 and k2 using the GLV method.
 *
 * @param {BigInt} k - The scalar to decompose
 * @param {[[BigInt, BigInt], [BigInt, BigInt]]} basis - The reduced basis vectors
 * @param {BigInt} n - The order of the curve
 * @returns {[BigInt, BigInt]} - A tuple (k1, k2) such that k ≡ k1 + k2*lambda (mod n)
 */
function decomposeScalar(k, basis, n) {
  const [v1, v2] = basis;

  // Calculate the determinant of the basis
  const det = v1[0] * v2[1] - v1[1] * v2[0];

  // Use Babai's round-off algorithm:
  // Calculate continuous coordinates in the basis
  const c1 = divNearest(k * v2[1], det);
  const c2 = divNearest(-k * v1[1], det);

  // Calculate the closest lattice point to (k, 0)
  const b1 = c1 * v1[0] + c2 * v2[0];
  const b2 = c1 * v1[1] + c2 * v2[1];

  // Calculate k1 = k - b1 (mod n) and k2 = -b2 (mod n)
  const k1 = mod(k - b1, n);
  const k2 = mod(-b2, n);

  return [k1, k2];
}

function powMod(num, power, modulus) {
  if (power < 0n) throw new Error('invalid exponent, negatives unsupported');
  if (power === 0n) return 1n;
  if (power === 1n) return num;
  let p = 1n;
  let d = num;
  while (power > 0n) {
    if (power & 1n) p = mod(p * d, modulus);
    d = mod(d * d, modulus);
    power >>= 1n;
  }
  return p;
}

// There are 3 cube roots of unity (1): 1, ω, ω2.
// One of them is trivial (1).
// To calculate `cbrt(1) mod prime`:
// β is ∛1 mod p: `β = x^(p-1)/3`
// λ is ∛1 mod n: `λ = x^(n-1)/3`
function findRootsOfUnity(fieldOrder) {
  let roots;
  let i = 2n;
  while (!roots) {
    const rootCandidate = powMod(i++, (fieldOrder - 1n) / 3n, fieldOrder);
    if (rootCandidate !== 1n) {
      const root = rootCandidate;
      const root2 = mod(root * root, fieldOrder);
      roots = [root, root2]
    }
  }
  return roots;
}

const hex = (n) => {
  const _16 = n.toString(16);
  const abs = n < 0 ? _16.slice(1) : _16;
  const pref = n < 0 ? '-0x' : '0x';
  return pref + abs;
};
export const config = { log: true };
const log = (...msgs) => {
  if (config.log) console.log(...msgs);
};
const logarr = (title, arr_) => log(`${title} = [\n  ${arr_.map(hex).join(',\n  ')}\n]`);
// const hex = n => n < 0 ? '-0x' + : '0x' + n.toString(16);
// Example usage
export function calcEndo(p, n) {
  const start = Date.now();
  log('Non-trivial cube roots of P (betas) and N (lambdas):');
  const betas = findRootsOfUnity(p);
  const lambdas = findRootsOfUnity(n);
  const basises = lambdas.map(l => calculateGlvBasis(n, l));
  console.log(basises);
  // logarr('betas', betas);
  // logarr('lambdas', lambdas);
  // logarr('basises', basises);
  // log('lambdas', lambdas.map(hex).join(', '));
  // log('betas  ', betas.map(hex).join(', '));
  // 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72n;
  let lambdaIndex = 0;
  for (let lambda of lambdas) {
    const basis = calculateGlvBasis(n, lambda);

    log();
    log(`Calculated reduced basis vectors of lambda #${lambdaIndex} for GLV decomposition:`);
    logarr('v1', basis[0]);
    logarr('v2', basis[1]);
    const end = Date.now();
    log('Calculated endomorphism in', end - start, 'ms');

    // Test with a scalar
    const k = 2n ** 255n - 19n; // Example scalar
    const [k1, k2] = decomposeScalar(k, basis, n);

    log();
    log('Decomposing scalar s:');
    log(`s = ${hex(k)}`);
    log(`k1 = ${hex(k1)}`);
    log(`k2 = ${hex(k2)}`);

    // Verify: k ≡ k1 + k2*lambda (mod n)
    const result = mod(k1 + k2 * lambda, n);
    log(`\nVerification:`);
    log(`k1 + k2*lambda (mod n) = ${hex(result)}`);
    log(`Original k (mod n)     = ${hex(mod(k, n))}`);
    log(`Match: ${result === mod(k, n)}`);

    // Check the sizes of k1 and k2 compared to k
    log(`\nSize comparison:`);
    log(`|k| ≈ ${k.toString(2).length} bits`);
    log(`|k1| ≈ ${k1.toString(2).length} bits`);
    log(`|k2| ≈ ${k2.toString(2).length} bits`);
    log(`Theoretical target: ~${Math.floor(n.toString(2).length / 2)} bits (sqrt(n))`);
  }
  return {
    betas,
    lambdas,
    basises
  }
}

// secp256k1 parameters
// const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
// const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
// calcEndo(p, n, 0);

// assert BETA != F(1)
// assert BETA^3 == F(1)
// assert BETA^2 + BETA + 1 == 0

// assert LAMBDA != Z(1)
// assert LAMBDA^3 == Z(1)
// assert LAMBDA^2 + LAMBDA + 1 == 0
// assert Integer(LAMBDA)*G == C(BETA*G[0], G[1])
