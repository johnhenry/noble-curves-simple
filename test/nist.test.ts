import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual, throws } from 'node:assert';
import { hexToBytes as bytes, bytesToHex, utf8ToBytes } from '../abstract/utils.js';
import { DER } from '../abstract/weierstrass.js';
import { p256, p384, p521, secp256r1, secp384r1, secp521r1 } from '../nist.js';
import { secp256k1 } from '../secp256k1.js';
import { p192, p224, secp192r1, secp224r1 } from './_more-curves.helpers.js';
import { json } from './utils.ts';
const ecdsa = json('./wycheproof/ecdsa_test.json');
const ecdh = json('./wycheproof/ecdh_test.json');
const rfc6979 = json('./vectors/rfc6979.json');
const endoVectors = json('./vectors/secp256k1/endomorphism.json');

const ecdh_secp224r1_test = json('./wycheproof/ecdh_secp224r1_test.json');
const ecdh_secp256r1_test = json('./wycheproof/ecdh_secp256r1_test.json');
const ecdh_secp256k1_test = json('./wycheproof/ecdh_secp256k1_test.json');
const ecdh_secp384r1_test = json('./wycheproof/ecdh_secp384r1_test.json');
const ecdh_secp521r1_test = json('./wycheproof/ecdh_secp521r1_test.json');
// Tests with custom hashes
const secp224r1_sha224_test = json('./wycheproof/ecdsa_secp224r1_sha224_test.json');
const secp224r1_sha256_test = json('./wycheproof/ecdsa_secp224r1_sha256_test.json');
const secp224r1_sha3_224_test = json('./wycheproof/ecdsa_secp224r1_sha3_224_test.json');
const secp224r1_sha3_256_test = json('./wycheproof/ecdsa_secp224r1_sha3_256_test.json');
const secp224r1_sha3_512_test = json('./wycheproof/ecdsa_secp224r1_sha3_512_test.json');
const secp224r1_sha512_test = json('./wycheproof/ecdsa_secp224r1_sha512_test.json');
const secp224r1_shake128_test = json('./wycheproof/ecdsa_secp224r1_shake128_test.json');

const secp256k1_sha256_bitcoin_test = json('./wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json');
const secp256k1_sha256_test = json('./wycheproof/ecdsa_secp256k1_sha256_test.json');
const secp256k1_sha3_256_test = json('./wycheproof/ecdsa_secp256k1_sha3_256_test.json');
const secp256k1_sha3_512_test = json('./wycheproof/ecdsa_secp256k1_sha3_512_test.json');
const secp256k1_sha512_test = json('./wycheproof/ecdsa_secp256k1_sha512_test.json');
const secp256k1_shake128_test = json('./wycheproof/ecdsa_secp256k1_shake128_test.json');
const secp256k1_shake256_test = json('./wycheproof/ecdsa_secp256k1_shake256_test.json');

const secp256r1_sha256_test = json('./wycheproof/ecdsa_secp256r1_sha256_test.json');
const secp256r1_sha3_256_test = json('./wycheproof/ecdsa_secp256r1_sha3_256_test.json');
const secp256r1_sha3_512_test = json('./wycheproof/ecdsa_secp256r1_sha3_512_test.json');
const secp256r1_sha512_test = json('./wycheproof/ecdsa_secp256r1_sha512_test.json');
const secp256r1_shake128_test = json('./wycheproof/ecdsa_secp256r1_shake128_test.json');

const secp384r1_sha384_test = json('./wycheproof/ecdsa_secp384r1_sha384_test.json');
const secp384r1_sha3_384_test = json('./wycheproof/ecdsa_secp384r1_sha3_384_test.json');
const secp384r1_sha3_512_test = json('./wycheproof/ecdsa_secp384r1_sha3_512_test.json');
const secp384r1_sha512_test = json('./wycheproof/ecdsa_secp384r1_sha512_test.json');
const secp384r1_shake256_test = json('./wycheproof/ecdsa_secp384r1_shake256_test.json');

const secp521r1_sha3_512_test = json('./wycheproof/ecdsa_secp521r1_sha3_512_test.json');
const secp521r1_sha512_test = json('./wycheproof/ecdsa_secp521r1_sha512_test.json');
const secp521r1_shake256_test = json('./wycheproof/ecdsa_secp521r1_shake256_test.json');

// TODO: maybe add to noble-hashes?
const wrapShake = (shake, dkLen) => {
  const hashC = (msg) => shake(msg, { dkLen });
  hashC.outputLen = dkLen;
  hashC.blockLen = shake.blockLen;
  hashC.create = () => shake.create({ dkLen });
  return hashC;
};
const shake128_224 = wrapShake(shake128, 224 / 8);
const shake128_256 = wrapShake(shake128, 256 / 8);
const shake256_256 = wrapShake(shake256, 256 / 8);
const shake256_384 = wrapShake(shake256, 384 / 8);
const shake256_512 = wrapShake(shake256, 512 / 8);

const hex = bytesToHex;

// prettier-ignore
const NIST = {
  secp192r1, P192: p192,
  secp224r1, P224: p224,
  secp256r1, P256: p256,
  secp384r1, P384: p384,
  secp521r1, P521: p521,
  secp256k1,
};

// describe('NIST curves', () => {});
should('fields', () => {
  const vectors = {
    secp192r1: 0xfffffffffffffffffffffffffffffffeffffffffffffffffn,
    secp224r1: 0xffffffffffffffffffffffffffffffff000000000000000000000001n,
    secp256r1: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    secp256k1: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    secp384r1:
      0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
    secp521r1:
      0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  };
  for (const n in vectors) deepStrictEqual(NIST[n].CURVE.Fp.ORDER, vectors[n]);
});

// We don't support ASN.1 encoding of points. For tests we've implemented quick
// and dirty parser: take X last bytes of ASN.1 encoded sequence.
// If that doesn't work, we ignore such vector.
function verifyECDHVector(test, curve) {
  if (test.flags.includes('InvalidAsn')) return; // Ignore invalid ASN
  if (test.result === 'valid' || test.result === 'acceptable') {
    const fnLen = curve.CURVE.nByteLength; // 32 for P256
    const fpLen = curve.CURVE.Fp.BYTES; // 32 for P256
    const encodedHexLen = fpLen * 2 * 2 + 2; // 130 (65 * 2) for P256
    const pubB = test.public.slice(-encodedHexLen); // slice(-130) for P256
    let privA = test.private;

    // Some wycheproof vectors are padded with 00 (because c6 > 128 and would be negative number otherwise):
    // 00c6cafb74e2a50c83b3d232c4585237f44d4c5433c4b3f50ce978e6aeda3a4f5d
    // instead of
    // c6cafb74e2a50c83b3d232c4585237f44d4c5433c4b3f50ce978e6aeda3a4f5d
    if (privA.length / 2 === fnLen + 1 && privA.startsWith('00')) privA = privA.slice(2);
    // privA = DER._int.decode(privA);
    if (!curve.utils.isValidPrivateKey(privA)) return; // Ignore invalid private key size
    try {
      curve.ProjectivePoint.fromHex(pubB);
    } catch (e) {
      if (e.message.startsWith('invalid Point, expected length')) return; // Ignore
      throw e;
    }
    const shared = curve.getSharedSecret(privA, pubB).subarray(1);
    deepStrictEqual(hex(shared), test.shared, 'valid');
  } else if (test.result === 'invalid') {
    let failed = false;
    try {
      curve.getSharedSecret(test.private, test.public);
    } catch (error) {
      failed = true;
    }
    deepStrictEqual(failed, true, 'invalid');
  } else throw new Error('unknown test result');
}

describe('wycheproof ECDH', () => {
  for (const group of ecdh.testGroups) {
    const curve = NIST[group.curve];
    if (!curve) continue;
    should(group.curve, () => {
      for (const test of group.tests) {
        verifyECDHVector(test, curve);
      }
    });
  }

  // More per curve tests
  const WYCHEPROOF_ECDH = {
    p224: {
      curve: p224,
      tests: [ecdh_secp224r1_test],
    },
    p256: {
      curve: p256,
      tests: [ecdh_secp256r1_test],
    },
    secp256k1: {
      curve: secp256k1,
      tests: [ecdh_secp256k1_test],
    },
    p384: {
      curve: p384,
      tests: [ecdh_secp384r1_test],
    },
    p521: {
      curve: p521,
      tests: [ecdh_secp521r1_test],
    },
  };

  for (const name in WYCHEPROOF_ECDH) {
    const { curve, tests } = WYCHEPROOF_ECDH[name];
    for (let i = 0; i < tests.length; i++) {
      const curveTests = tests[i];
      for (let j = 0; j < curveTests.testGroups.length; j++) {
        const group = curveTests.testGroups[j];
        should(`additional ${name} (${group.tests.length})`, () => {
          for (const test of group.tests) {
            verifyECDHVector(test, curve);
          }
        });
      }
    }
  }
});

const WYCHEPROOF_ECDSA = {
  p224: {
    curve: p224,
    hashes: {
      sha224: {
        hash: sha224,
        tests: [secp224r1_sha224_test],
      },
      sha256: {
        hash: sha256,
        tests: [secp224r1_sha256_test],
      },
      sha3_224: {
        hash: sha3_224,
        tests: [secp224r1_sha3_224_test],
      },
      sha3_256: {
        hash: sha3_256,
        tests: [secp224r1_sha3_256_test],
      },
      sha3_512: {
        hash: sha3_512,
        tests: [secp224r1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp224r1_sha512_test],
      },
      shake128: {
        hash: shake128_224,
        tests: [secp224r1_shake128_test],
      },
    },
  },
  secp256k1: {
    curve: secp256k1,
    hashes: {
      sha256: {
        hash: sha256,
        tests: [secp256k1_sha256_test, secp256k1_sha256_bitcoin_test],
      },
      sha3_256: {
        hash: sha3_256,
        tests: [secp256k1_sha3_256_test],
      },
      sha3_512: {
        hash: sha3_512,
        tests: [secp256k1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp256k1_sha512_test],
      },
      shake128: {
        hash: shake128_256,
        tests: [secp256k1_shake128_test],
      },
      shake256: {
        hash: shake256_256,
        tests: [secp256k1_shake256_test],
      },
    },
  },
  p256: {
    curve: p256,
    hashes: {
      sha256: {
        hash: sha256,
        tests: [secp256r1_sha256_test],
      },
      sha3_256: {
        hash: sha3_256,
        tests: [secp256r1_sha3_256_test],
      },
      sha3_512: {
        hash: sha3_512,
        tests: [secp256r1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp256r1_sha512_test],
      },
      shake128: {
        hash: shake128_256,
        tests: [secp256r1_shake128_test],
      },
    },
  },
  p384: {
    curve: p384,
    hashes: {
      sha384: {
        hash: sha384,
        tests: [secp384r1_sha384_test],
      },
      sha3_384: {
        hash: sha3_384,
        tests: [secp384r1_sha3_384_test],
      },
      sha3_512: {
        hash: sha3_512,
        tests: [secp384r1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp384r1_sha512_test],
      },
      shake256: {
        hash: shake256_384,
        tests: [secp384r1_shake256_test],
      },
    },
  },
  p521: {
    curve: p521,
    hashes: {
      sha3_512: {
        hash: sha3_512,
        tests: [secp521r1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp521r1_sha512_test],
      },
      shake256: {
        hash: shake256_512,
        tests: [secp521r1_shake256_test],
      },
    },
  },
};

function runWycheproof(name, CURVE, group, index) {
  const key = group.publicKey;
  const pubKey = CURVE.ProjectivePoint.fromHex(key.uncompressed);
  deepStrictEqual(pubKey.x, BigInt(`0x${key.wx}`));
  deepStrictEqual(pubKey.y, BigInt(`0x${key.wy}`));
  const pubR = pubKey.toRawBytes();
  for (const test of group.tests) {
    const m = CURVE.CURVE.hash(bytes(test.msg));
    const { sig } = test;
    if (test.result === 'valid' || test.result === 'acceptable') {
      const verified = CURVE.verify(bytes(sig), m, pubR, { lowS: name === 'secp256k1' });
      if (name === 'secp256k1') {
        // lowS: true for secp256k1
        deepStrictEqual(verified, !CURVE.Signature.fromDER(bytes(sig)).hasHighS(), `${index}: valid`);
      } else {
        deepStrictEqual(verified, true, `${index}: valid`);
      }
    } else if (test.result === 'invalid') {
      let failed = false;
      try {
        failed = !CURVE.verify(sig, m, pubR);
      } catch (error) {
        failed = true;
      }
      deepStrictEqual(failed, true, `${index}: invalid`);
    } else throw new Error('unknown test result');
  }
}

describe('wycheproof ECDSA', () => {
  should('generic', () => {
    for (const group of ecdsa.testGroups) {
      // Tested in secp256k1.test.js
      let CURVE = NIST[group.key.curve];
      if (!CURVE) continue;
      const hasLowS = group.key.curve === 'secp256k1';
      if (group.key.curve === 'secp224r1' && group.sha !== 'SHA-224') {
        if (group.sha === 'SHA-256') CURVE = CURVE.create(sha256);
      }
      const pubKey = CURVE.ProjectivePoint.fromHex(group.key.uncompressed);
      deepStrictEqual(pubKey.x, BigInt(`0x${group.key.wx}`));
      deepStrictEqual(pubKey.y, BigInt(`0x${group.key.wy}`));
      for (const test of group.tests) {
        if (['Hash weaker than DL-group'].includes(test.comment)) {
          continue;
        }
        // These old Wycheproof vectors which still accept missing zero, new one is not.
        if (test.flags.includes('MissingZero') && test.result === 'acceptable')
          test.result = 'invalid';
        const m = CURVE.CURVE.hash(bytes(test.msg));
        if (test.result === 'valid' || test.result === 'acceptable') {
          const verified = CURVE.verify(test.sig, m, pubKey.toHex(), { lowS: hasLowS });
          if (hasLowS) {
            // lowS: true for secp256k1
            deepStrictEqual(verified, !CURVE.Signature.fromDER(test.sig).hasHighS(), `valid`);
          } else {
            deepStrictEqual(verified, true, `valid`);
          }
        } else if (test.result === 'invalid') {
          let failed = false;
          try {
            failed = !CURVE.verify(test.sig, m, pubKey.toHex());
          } catch (error) {
            failed = true;
          }
          deepStrictEqual(failed, true, 'invalid');
        } else throw new Error('unknown test result');
      }
    }
  });
  for (const name in WYCHEPROOF_ECDSA) {
    const { curve, hashes } = WYCHEPROOF_ECDSA[name];
    describe(name, () => {
      for (const hName in hashes) {
        const { hash, tests } = hashes[hName];
        const CURVE = curve.create(hash);
        should(`${name}/${hName}`, () => {
          for (let i = 0; i < tests.length; i++) {
            const groups = tests[i].testGroups;
            for (let j = 0; j < groups.length; j++) {
              const group = groups[j];
              runWycheproof(name, CURVE, group, `${i}/${j}`);
            }
          }
        });
      }
    });
  }
});

const hexToBigint = (hex) => BigInt(`0x${hex}`);
describe('RFC6979', () => {
  for (const v of rfc6979) {
    should(v.curve, () => {
      const hasLowS = v.curve === 'secp256k1';
      const curve = NIST[v.curve];
      deepStrictEqual(curve.CURVE.n, hexToBigint(v.q));
      const pubKey = curve.getPublicKey(v.private);
      const pubPoint = curve.ProjectivePoint.fromHex(pubKey);
      deepStrictEqual(pubPoint.x, hexToBigint(v.Ux));
      deepStrictEqual(pubPoint.y, hexToBigint(v.Uy));
      for (const c of v.cases) {
        const h = curve.CURVE.hash(utf8ToBytes(c.message));
        const opts = { lowS: hasLowS };
        const sigObj = curve.sign(h, v.private, opts);
        deepStrictEqual(sigObj.r, hexToBigint(c.r), 'R');
        deepStrictEqual(sigObj.s, hexToBigint(c.s), 'S');
        deepStrictEqual(curve.verify(sigObj.toDERRawBytes(), h, pubKey, opts), true, 'verify(1)');
        deepStrictEqual(curve.verify(sigObj, h, pubKey, opts), true, 'verify(2)');
      }
    });
  }
});

should('properly add leading zero to DER', () => {
  // Valid DER
  deepStrictEqual(
    DER.toSig(
      '303c021c70049af31f8348673d56cece2b27e587a402f2a48f0b21a7911a480a021c2840bf24f6f66be287066b7cbf38788e1b7770b18fd1aa6a26d7c6dc'
    ),
    {
      r: 11796871166002955884468185727465595477481802908758874298363724580874n,
      s: 4239126896857047637966364941684493209162496401998708914961872570076n,
    }
  );
  // Invalid DER (missing trailing zero)
  throws(() =>
    DER.toSig(
      '303c021c70049af31f8348673d56cece2b27e587a402f2a48f0b21a7911a480a021cd7bf40db0909941d78f9948340c69e14c5417f8c840b7edb35846361'
    )
  );
  // Correctly adds trailing zero
  deepStrictEqual(
    DER.hexFromSig({
      r: 11796871166002955884468185727465595477481802908758874298363724580874n,
      s: 22720819770293592156700650145335132731295311312425682806720849797985n,
    }),
    '303d021c70049af31f8348673d56cece2b27e587a402f2a48f0b21a7911a480a021d00d7bf40db0909941d78f9948340c69e14c5417f8c840b7edb35846361'
  );
});

should('have proper GLV endomorphism logic in secp256k1', () => {
  const Point = secp256k1.ProjectivePoint;
  for (let item of endoVectors) {
    const point = Point.fromAffine({ x: BigInt(item.ax), y: BigInt(item.ay) });
    const c = point.multiplyUnsafe(BigInt(item.scalar)).toAffine();
    deepStrictEqual(c.x, BigInt(item.cx));
    deepStrictEqual(c.y, BigInt(item.cy));
  }
});

should('handle edge-case in P521', () => {
  // elliptic 6.6.0 edge-case
  const privKey = bytes(
    '01535d22d63de9195efd4c41358ddc89c68b6cc202b558fbf48a09e95dddf953afc1b4cfed6df0f3330f986735085e367fd07030c3ab49dcd3461197b00f09a064fb'
  );
  const msg = bytes('12f830e9591916ec');
  const sig =
    '308188024201e92eeaf15414d4af3ee933825131867b6cb10234f28336ac976a' +
    '99127139f23100458a9ee7184bfa64540ba385331eb3b469f491b3da013c42ad' +
    '154a5907f554f0024200db3703c6d51b8a85c10c21b7643fe751781a7ad5708e' +
    '3a944107f6da086afdc8532765871a9cabc81cec0f5b28ee59f0c72b48b72a39' +
    'ae2d230dfb03afb9968a94';

  // const fault =
  //   '30818702415efa2e9fb7d988bf19e750bc6235364ecfdbe649f1a3b9a89af077' +
  //   'eefd7f8dd979f371b28d77b885cf369a100c0d326804fc4b9ab681a39d212b41' +
  //   'a85b126b00130242008fbcbd46e829ca57a8e25c5deb30b5064366cae2f4bd82' +
  //   '14e8dafcb8f6a7d59757ec8896981466d6f0eb5ca07dcaa46e6bb86eb20471e4' +
  //   '5702429ef132e0c96615';

  const hex = secp521r1.sign(msg, privKey, { lowS: false, prehash: true }).toDERHex();
  deepStrictEqual(hex, sig);
});

should.runWhen(import.meta.url);
