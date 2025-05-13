import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import { json } from './utils.js';
// Generic tests for all curves in package
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { shake128, shake256 } from '@noble/hashes/sha3.js';
import { expand_message_xmd, expand_message_xof } from '../abstract/hash-to-curve.js';
import { utf8ToBytes } from '../abstract/utils.js';
import { bls12_381 } from '../bls12-381.js';
import { ed25519_hasher } from '../ed25519.js';
import { ed448_hasher } from '../ed448.js';
import * as nist from '../nist.js';
import { secp256k1_hasher } from '../secp256k1.js';
// XMD
const xmd_sha256_38 = json('./hash-to-curve/expand_message_xmd_SHA256_38.json');
const xmd_sha256_256 = json('./hash-to-curve/expand_message_xmd_SHA256_256.json');
const xmd_sha512_38 = json('./hash-to-curve/expand_message_xmd_SHA512_38.json');
// XOF
const xof_shake128_36 = json('./hash-to-curve/expand_message_xof_SHAKE128_36.json');
const xof_shake128_256 = json('./hash-to-curve/expand_message_xof_SHAKE128_256.json');
const xof_shake256_36 = json('./hash-to-curve/expand_message_xof_SHAKE256_36.json');
// P256
const p256_ro = json('./hash-to-curve/P256_XMD_SHA-256_SSWU_RO_.json');
const p256_nu = json('./hash-to-curve/P256_XMD_SHA-256_SSWU_NU_.json');
// P384
const p384_ro = json('./hash-to-curve/P384_XMD_SHA-384_SSWU_RO_.json');
const p384_nu = json('./hash-to-curve/P384_XMD_SHA-384_SSWU_NU_.json');
// P521
const p521_ro = json('./hash-to-curve/P521_XMD_SHA-512_SSWU_RO_.json');
const p521_nu = json('./hash-to-curve/P521_XMD_SHA-512_SSWU_NU_.json');
// secp256k1
const secp256k1_ro = json('./hash-to-curve/secp256k1_XMD_SHA-256_SSWU_RO_.json');
const secp256k1_nu = json('./hash-to-curve/secp256k1_XMD_SHA-256_SSWU_NU_.json');
// bls-G1
const g1_ro = json('./hash-to-curve/BLS12381G1_XMD_SHA-256_SSWU_RO_.json');
const g1_nu = json('./hash-to-curve/BLS12381G1_XMD_SHA-256_SSWU_NU_.json');
// bls-G2
const g2_ro = json('./hash-to-curve/BLS12381G2_XMD_SHA-256_SSWU_RO_.json');
const g2_nu = json('./hash-to-curve/BLS12381G2_XMD_SHA-256_SSWU_NU_.json');
// ed25519
const ed25519_ro = json('./hash-to-curve/edwards25519_XMD_SHA-512_ELL2_RO_.json');
const ed25519_nu = json('./hash-to-curve/edwards25519_XMD_SHA-512_ELL2_NU_.json');
// ed448
const ed448_ro = json('./hash-to-curve/edwards448_XOF_SHAKE256_ELL2_RO_.json');
const ed448_nu = json('./hash-to-curve/edwards448_XOF_SHAKE256_ELL2_NU_.json');

function testExpandXMD(hash, vectors) {
  describe(`${vectors.hash}/${vectors.DST.length}`, () => {
    for (let i = 0; i < vectors.tests.length; i++) {
      const t = vectors.tests[i];
      should(`${vectors.hash}/${vectors.DST.length}/${i}`, () => {
        const p = expand_message_xmd(
          utf8ToBytes(t.msg),
          utf8ToBytes(vectors.DST),
          Number.parseInt(t.len_in_bytes),
          hash
        );
        deepStrictEqual(bytesToHex(p), t.uniform_bytes);
      });
    }
  });
}

describe('expand_message_xmd', () => {
  testExpandXMD(sha256, xmd_sha256_38);
  testExpandXMD(sha256, xmd_sha256_256);
  testExpandXMD(sha512, xmd_sha512_38);
});

function testExpandXOF(hash, vectors) {
  describe(`${vectors.hash}/${vectors.DST.length}`, () => {
    for (let i = 0; i < vectors.tests.length; i++) {
      const t = vectors.tests[i];
      should(`${i}`, () => {
        const p = expand_message_xof(
          utf8ToBytes(t.msg),
          utf8ToBytes(vectors.DST),
          Number.parseInt(t.len_in_bytes),
          vectors.k,
          hash
        );
        deepStrictEqual(bytesToHex(p), t.uniform_bytes);
      });
    }
  });
}

describe('expand_message_xof', () => {
  testExpandXOF(shake128, xof_shake128_36);
  testExpandXOF(shake128, xof_shake128_256);
  testExpandXOF(shake256, xof_shake256_36);
});

function stringToFp(s) {
  // bls-G2 support
  if (s.includes(',')) {
    const [c0, c1] = s.split(',').map(BigInt);
    return { c0, c1 };
  }
  return BigInt(s);
}

function testCurve(hasher, ro, nu) {
  describe(`${ro.curve}/${ro.ciphersuite}`, () => {
    for (let i = 0; i < ro.vectors.length; i++) {
      const t = ro.vectors[i];
      should(`(${i})`, () => {
        const p = hasher
          .hashToCurve(utf8ToBytes(t.msg), {
            DST: ro.dst,
          })
          .toAffine();
        deepStrictEqual(p.x, stringToFp(t.P.x), 'Px');
        deepStrictEqual(p.y, stringToFp(t.P.y), 'Py');
      });
    }
  });
  describe(`${nu.curve}/${nu.ciphersuite}`, () => {
    for (let i = 0; i < nu.vectors.length; i++) {
      const t = nu.vectors[i];
      should(`(${i})`, () => {
        const p = hasher
          .encodeToCurve(utf8ToBytes(t.msg), {
            DST: nu.dst,
          })
          .toAffine();
        deepStrictEqual(p.x, stringToFp(t.P.x), 'Px');
        deepStrictEqual(p.y, stringToFp(t.P.y), 'Py');
      });
    }
  });
}

testCurve(nist.p256_hasher, p256_ro, p256_nu);
testCurve(nist.p384_hasher, p384_ro, p384_nu);
testCurve(nist.p521_hasher, p521_ro, p521_nu);
testCurve(bls12_381.G1, g1_ro, g1_nu);
testCurve(bls12_381.G2, g2_ro, g2_nu);
testCurve(secp256k1_hasher, secp256k1_ro, secp256k1_nu);
testCurve(ed25519_hasher, ed25519_ro, ed25519_nu);
testCurve(ed448_hasher, ed448_ro, ed448_nu);

should.runWhen(import.meta.url);
