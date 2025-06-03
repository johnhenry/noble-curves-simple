import { p384_hasher, p384 as p384n } from './nist.js';
export const p384 = p384n;
export const secp384r1 = p384n;
export const hashToCurve = /* @__PURE__ */ (() => p384_hasher.hashToCurve)();
export const encodeToCurve = /* @__PURE__ */ (() => p384_hasher.encodeToCurve)();
/** @deprecated Use `import { p384_hasher } from "@noble/curves/nist"` module. */
