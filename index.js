let base58check = require('bs58check')
let createHash = require('create-hash')
let createHmac = require('create-hmac')
let typeforce = require('typeforce')
let BigInteger = require('bigi')
let ecurve = require('ecurve')
let curve = ecurve.getCurveByName('secp256k1')

let UINT31_MAX = Math.pow(2, 31) - 1
function UInt31 (value) {
  return typeforce.UInt32(value) && value <= UINT31_MAX
}

function BIP32Path (value) {
  return typeforce.String(value) && value.match(/^(m\/)?(\d+'?\/)*\d+'?$/)
}
BIP32Path.toJSON = function () { return 'BIP32 derivation path' }

function Node (d, Q, chainCode) {
  typeforce(typeforce.tuple(
    typeforce.maybe(typeforce.BufferN(32)),
    typeforce.maybe(typeforce.BufferN(33)), // compressed only
    typeforce.BufferN(32)
  ), arguments)
  if (!d && !Q) throw new TypeError('Missing keyPair data')

  this.keyPair = { d, Q }
  this.chainCode = chainCode
  this.depth = 0
  this.index = 0
  this.parentFingerprint = 0x00000000
}

Node.HIGHEST_BIT = 0x80000000
Node.LENGTH = 78
Node.MASTER_SECRET = Buffer.from('Bitcoin seed', 'utf8')

// TODO
// Node.prototype.getAddress = function () {
//   return this.keyPair.getAddress()
// }

Node.prototype.getIdentifier = function () {
  let h = createHash('rmd160').update(this.keyPair.Q).digest()
  return createHash('sha256').update(h).digest()
}

Node.prototype.getFingerprint = function () {
  return this.getIdentifier().slice(0, 4)
}

Node.prototype.neutered = function () {
  let neuteredKeyPair = { Q: this.keyPair.Q }
  let neutered = new Node(neuteredKeyPair, this.chainCode)
  neutered.depth = this.depth
  neutered.index = this.index
  neutered.parentFingerprint = this.parentFingerprint

  return neutered
}

// TODO
// Node.prototype.sign = function (hash) {
//   return this.keyPair.sign(hash)
// }
// Node.prototype.verify = function (hash, signature) {
//   return this.keyPair.verify(hash, signature)
// }

Node.prototype.getPublicKey = function () {
  return this.keyPair.Q
}

Node.prototype.toBase58 = function (bip32Constants) {
  let version = (!this.isNeutered()) ? bip32Constants.private : bip32Constants.public
  let buffer = Buffer.allocUnsafe(78)

  // 4 bytes: version bytes
  buffer.writeUInt32BE(version, 0)

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
  buffer.writeUInt8(this.depth, 4)

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  buffer.writeUInt32BE(this.parentFingerprint, 5)

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in big endian. (0x00000000 if master key)
  buffer.writeUInt32BE(this.index, 9)

  // 32 bytes: the chain code
  this.chainCode.copy(buffer, 13)

  // 33 bytes: the [padded] private key, or
  if (!this.isNeutered()) {
    // 0x00 + k for private keys
    buffer.writeUInt8(0, 45)
    this.keyPair.d.copy(buffer, 46)

  // 33 bytes: the public key
  } else {
    // X9.62 encoding for public keys
    this.keyPair.Q.copy(buffer, 45)
  }

  return base58check.encode(buffer)
}

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
Node.prototype.derive = function (index) {
  typeforce(typeforce.UInt32, index)

  let isHardened = index >= Node.HIGHEST_BIT
  let data = Buffer.allocUnsafe(37)

  // Hardened child
  if (isHardened) {
    if (this.isNeutered()) throw new TypeError('Could not derive hardened child key')

    // data = 0x00 || ser256(kpar) || ser32(index)
    data[0] = 0x00
    this.keyPair.d.toBuffer(32).copy(data, 1)
    data.writeUInt32BE(index, 33)

  // Normal child
  } else {
    // data = serP(point(kpar)) || ser32(index)
    //      = serP(Kpar) || ser32(index)
    this.keyPair.getPublicKeyBuffer().copy(data, 0)
    data.writeUInt32BE(index, 33)
  }

  let I = createHmac('sha512', this.chainCode).update(data).digest()
  let IL = I.slice(0, 32)
  let IR = I.slice(32)
  let pIL = BigInteger.fromBuffer(IL)

  // In case parse256(IL) >= n, proceed with the next value for i
  if (pIL.compareTo(curve.n) >= 0) {
    return this.derive(index + 1)
  }

  // Private parent key -> private child key
  let hd
  if (!this.isNeutered()) {
    // ki = parse256(IL) + kpar (mod n)
    let ki = pIL.add(this.keyPair.d).mod(curve.n)

    // In case ki == 0, proceed with the next value for i
    if (ki.signum() === 0) return this.derive(index + 1)

    hd = new Node(ki, null, IR)

  // Public parent key -> public child key
  } else {
    // Ki = point(parse256(IL)) + Kpar
    //    = G*IL + Kpar
    let Ki = curve.G.multiply(pIL).add(this.keyPair.Q)

    // In case Ki is the point at infinity, proceed with the next value for i
    if (curve.isInfinity(Ki)) return this.derive(index + 1)

    hd = new Node(null, Ki, IR)
  }

  hd.depth = this.depth + 1
  hd.index = index
  hd.parentFingerprint = this.getFingerprint().readUInt32BE(0)

  return hd
}

Node.prototype.deriveHardened = function (index) {
  typeforce(UInt31, index)

  // Only derives hardened private keys by default
  return this.derive(index + Node.HIGHEST_BIT)
}

// Private === not neutered
// Public === neutered
Node.prototype.isNeutered = function () {
  return !(this.keyPair.d)
}

Node.prototype.derivePath = function (path) {
  typeforce(BIP32Path, path)

  let splitPath = path.split('/')
  if (splitPath[0] === 'm') {
    if (this.parentFingerprint) throw new Error('Not a master node')

    splitPath = splitPath.slice(1)
  }

  return splitPath.reduce(function (prevHd, indexStr) {
    let index
    if (indexStr.slice(-1) === "'") {
      index = parseInt(indexStr.slice(0, -1), 10)
      return prevHd.deriveHardened(index)
    } else {
      index = parseInt(indexStr, 10)
      return prevHd.derive(index)
    }
  }, this)
}

function fromSeed (seed) {
  typeforce(typeforce.oneOf(typeforce.BufferN(16), typeforce.BufferN(32)), seed)

  if (seed.length < 16) throw new TypeError('Seed should be at least 128 bits')
  if (seed.length > 64) throw new TypeError('Seed should be at most 512 bits')

  let I = createHmac('sha512', Node.MASTER_SECRET).update(seed).digest()
  let IL = I.slice(0, 32)
  let IR = I.slice(32)
  let pIL = BigInteger.fromBuffer(IL)

  // In case parse256(IL) is 0 or >= n, the master key is invalid
  if (pIL.compareTo(BigInteger.ZERO) === 0 || pIL.compareTo(curve.n) >= 0) {
    throw new TypeError('Invalid seed')
  }

  return new Node(IL, null, IR)
}

function fromBase58 (string, bip32Constants) {
  let buffer = base58check.decode(string)
  if (buffer.length !== 78) throw new Error('Invalid buffer length')

  // 4 bytes: version bytes
  let version = buffer.readUInt32BE(0)

  if (version !== bip32Constants.private &&
    version !== bip32Constants.public) throw new Error('Invalid network version')

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
  let depth = buffer[4]

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  let parentFingerprint = buffer.readUInt32BE(5)
  if (depth === 0) {
    if (parentFingerprint !== 0x00000000) throw new Error('Invalid parent fingerprint')
  }

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in MSB order. (0x00000000 if master key)
  let index = buffer.readUInt32BE(9)
  if (depth === 0 && index !== 0) throw new Error('Invalid index')

  // 32 bytes: the chain code
  let chainCode = buffer.slice(13, 45)

  // 33 bytes: private key data (0x00 + k)
  let hd
  if (version === bip32Constants.private) {
    if (buffer.readUInt8(45) !== 0x00) throw new Error('Invalid private key')

    let d = buffer.slice(46, 78)
    hd = new Node(d, null, chainCode)

  // 33 bytes: public key data (0x02 + X or 0x03 + X)
  } else {
    let Q = ecurve.Point.decodeFrom(curve, buffer.slice(45, 78))
    // Q.compressed is assumed, if somehow this assumption is broken, `new Node` will throw

    // Verify that the X coordinate in the public point corresponds to a point on the curve.
    // If not, the extended public key is invalid.
    curve.validate(Q)

    hd = new Node(null, Q, chainCode)
  }

  hd.depth = depth
  hd.index = index
  hd.parentFingerprint = parentFingerprint

  return hd
}

module.exports = {
  fromBase58,
  fromSeed
}
