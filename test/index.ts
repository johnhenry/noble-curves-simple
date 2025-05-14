import { should } from 'micro-should';

// Should be first to catch obvious things
import './basic.test.ts';
import './bls12-381.test.ts';
import './bn254.test.ts';
import './ed25519-addons.test.ts';
import './ed25519.test.ts';
import './ed448-addons.test.ts';
import './ed448.test.ts';
import './hash-to-curve.test.ts';
import './jubjub.test.ts';
import './nist.test.ts';
import './poseidon.test.ts';
import './secp256k1-schnorr.test.ts';
import './secp256k1.test.ts';
import './utils.test.ts';

should.runWhen(import.meta.url);
