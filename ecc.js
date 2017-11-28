let secp256k1 = require('secp256k1')

function intAdd (a, b) {
  return secp256k1.privateKeyTweakAdd(a, b)
}

var EC_ZERO = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
var EC_UINT_MAX = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')

function intIsZero (a) {
  return a.equals(EC_ZERO)
}

function intVerify (value) {
//    return secp256k1.privateKeyVerify(a)
  return Buffer.isBuffer(value) &&
    value.length === 32 &&
    value.compare(EC_ZERO) > 0 && // > 0
    value.compare(EC_UINT_MAX) < 0 // < n-1
}

function pointAddTweak (q, tweak, compressed) {
  try {
    return secp256k1.publicKeyTweakAdd(q, tweak, compressed)
  } catch (e) {
    return null
  }
}

function pointDerive (d, compressed) {
  return secp256k1.publicKeyCreate(d, compressed)
}

function pointVerify (q, compressed) {
  if (!Buffer.isBuffer(q)) return false
  if (q.length < 33) return false

  switch (q[0]) {
    case 0x02:
    case 0x03:
      if (q.length !== 33) return false
      break
    case 0x04:
      if (q.length !== 65) return false
      if (compressed) return false
      break
    default:
      return false
  }

  return secp256k1.publicKeyVerify(q)
}

function ecdsaSign (hash, d) {
  return secp256k1.sign(hash, d).signature
}

function ecdsaVerify (hash, signature, Q) {
  return secp256k1.verify(hash, signature, Q)
}

module.exports = {
  intAdd,
  intIsZero,
  intVerify,
  pointAddTweak,
  pointDerive,
  pointVerify,
  ecdsaSign,
  ecdsaVerify
}
