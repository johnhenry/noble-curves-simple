// @ts-ignore
export { mod } from '../esm/abstract/modular.js';
export { bytesToNumberBE, numberToBytesBE } from '../esm/abstract/utils.js';
export { secp256k1 as secp } from '../esm/secp256k1.js';
import { secp256k1 as _secp } from '../esm/secp256k1.js';
export const sigFromDER = (der) => {
  return _secp.Signature.fromDER(der);
};
export const sigToDER = (sig) => sig.toDERHex();
export const selectHash = (secp) => secp.CURVE.hash;
export const normVerifySig = (s) => _secp.Signature.fromDER(s);
