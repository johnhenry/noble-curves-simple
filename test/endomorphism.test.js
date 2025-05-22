import { weierstrassN } from '../esm/abstract/weierstrass.js';
import { calcEndo, config } from './misc/endomorphism.js';

// TODO: calculate endomorphism
const SECP160K1 = {
  p: '0xfffffffffffffffffffffffffffffffeffffac73',
  n: '0x100000000000000000001b8fa16dfab9aca16b6b3',
  h: '0x1',
  a: '0x0',
  b: '0x7',
  Gx: '0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebb',
  Gy: '0x938cf935318fdced6bc28286531733c3f03c4fee',
};
const SECP192K1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffeffffee37',
  n: '0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d',
  h: '0x1',
  a: '0x0',
  b: '0x3',
  Gx: '0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d',
  Gy: '0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d',
};

const SECP224K1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d',
  n: '0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7',
  h: '0x1',
  a: '0x0',
  b: '0x5',
  Gx: '0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c',
  Gy: '0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5',
};

const SECP256K1 = {
  p: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
  n: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
  h: BigInt(1),
  a: BigInt(0),
  b: BigInt(7),
  Gx: BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
  Gy: BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
};

const curvesEndo = {
  // SECP160K1,
  SECP192K1,
  // SECP224K1,
  // SECP256K1
};
export const endoCurves = {};
config.log = false;
for (let [name, e] of Object.entries(curvesEndo)) {
  const p = BigInt(e.p);
  const n = BigInt(e.n);
  const params = {
    p: BigInt(p),
    a: BigInt(e.a),
    b: BigInt(e.b),
    Gx: BigInt(e.Gx),
    Gy: BigInt(e.Gy),
    n: n,
    h: BigInt(e.h),
  };
  console.log();
  console.log();
  const endo = calcEndo(p, n);
  console.log('calculating endo for', name);
  const hex = (n) => {
    const _16 = n.toString(16);
    // const abs = n < 0 ? _16.slice(1) : _16;
    // const pref = n < 0 ? '-0x' : '0x';
    // const res = pref + abs
    return _16;
  };
  console.log('betas', endo.betas.map(hex));
  console.log('lambdas', endo.lambdas.map(hex));
  console.log(
    'basises 1',
    endo.basises[0].map((b) => b.map(hex))
  );
  console.log(
    'basises 2',
    endo.basises[1].map((b) => b.map(hex))
  );
  const P_noEndo = weierstrassN(params);
  const P_endo0 = weierstrassN(params, {
    endo: {
      beta: endo.betas[0],
      // lambda: endo.lambdas[1],
      basises: endo.basises[1],
    },
  });
  const P_endo1 = weierstrassN(params, {
    endo: {
      beta: endo.betas[1],
      // lambda: endo.lambdas[1],
      basises: endo.basises[0],
    },
  });
  const points = [P_noEndo, P_endo0, P_endo1];
  const values = [
    3n,
    33333n,
    2n ** 33n,
    2n ** 150n - 12930n,
    2n ** 255n - 19n,
    2n ** 207n - 11n,
    2n ** 520n + 41290903n,
  ].map((i) => P_noEndo.Fn.create(i));
  for (let val of values) {
    console.log('curve', name);
    console.log('scalar', val);
    for (let p of points) {
      console.log(p.BASE.multiply(val).toString());
    }
  }
  // endoCurves[name] = createCurve(params, sha256);
}
