import { p256_hasher, p256 as p256n } from './nist.js';
export const p256 = p256n;
export const secp256r1 = p256n;
export const hashToCurve = /* @__PURE__ */ (() => p256_hasher.hashToCurve)();
export const encodeToCurve = /* @__PURE__ */ (() => p256_hasher.encodeToCurve)();
