import { p521_hasher, p521 as p521n } from './nist.js';
export const p521 = p521n;
export const secp521r1 = p521n;
export const hashToCurve = /* @__PURE__ */ (() => p521_hasher.hashToCurve)();
export const encodeToCurve = /* @__PURE__ */ (() => p521_hasher.encodeToCurve)();
