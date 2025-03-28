export function generateData(curve) {
  const priv = curve.utils.randomPrivateKey();
  const pub = curve.getPublicKey(priv);
  const msg = curve.utils.randomPrivateKey();
  const sig = curve.sign(msg, priv);
  return { priv, pub, msg, sig };
}

export function title(str) {
  console.log(`\x1b[36m# ${str}\x1b[0m`);
}
