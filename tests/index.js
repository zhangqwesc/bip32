var BIP32 = require('../')
var tape = require('tape')
var fixtures = require('./fixtures')
var LITECOIN = {
  wif: 0xb0,
  bip32: {
    public: 0x019da462,
    private: 0x019d9cfe
  }
}

var validAll = []
fixtures.valid.forEach(function (f) {
  f.master.network = f.network
  f.children.forEach(function (fc) {
    fc.network = f.network
    validAll.push(fc)
  })
  validAll.push(f.master)
})

validAll.forEach(function (f) {
  tape.test(f.base58Priv, function (t) {
    t.plan(18)

    var network
    if (f.network === 'litecoin') network = LITECOIN
    var hd = BIP32.fromBase58(f.base58Priv, network)

    t.equal(hd.chainCode.toString('hex'), f.chainCode)
    t.equal(hd.depth, f.depth >>> 0)
    t.equal(hd.index, f.index >>> 0)
    t.equal(hd.getFingerprint().toString('hex'), f.fingerprint)
    t.equal(hd.getIdentifier().toString('hex'), f.identifier)
    t.equal(hd.getPublicKey().toString('hex'), f.pubKey)
    t.equal(hd.toBase58(), f.base58Priv)
    t.equal(hd.toWIF(), f.wif)

    var nhd = BIP32.fromBase58(f.base58Priv, network).neutered()
    t.throws(function () { nhd.toWIF() }, /Missing private key/)
    t.equal(nhd.chainCode.toString('hex'), f.chainCode)
    t.equal(nhd.depth, f.depth >>> 0)
    t.equal(nhd.index, f.index >>> 0)
    t.equal(nhd.d, null) // internal
    t.equal(nhd.getFingerprint().toString('hex'), f.fingerprint)
    t.equal(nhd.getIdentifier().toString('hex'), f.identifier)
    t.equal(nhd.getPublicKey().toString('hex'), f.pubKey)
    t.equal(nhd.isNeutered(), true)
    t.equal(nhd.toBase58(), f.base58)
  })
})

/*
tape.test('fromSeed', function (t) {
  fixtures.valid.forEach(function (f) {
    var network
    if (f.network === 'litecoin') network = LITECOIN
    var hd = BIP32.fromSeed(Buffer.from(f.master.seed, 'hex'), network)

    t.equal(hd.keyPair.toWIF(), f.master.wif)
    t.equal(hd.chainCode.toString('hex'), f.master.chainCode)
  })

  tape.test('throws if IL is not within interval [1, n - 1] | IL === 0', function () {
    this.mock(BigInteger).expects('fromBuffer')
      .once().returns(BigInteger.ZERO)

    t.throws(function () {
      BIP32.fromSeedHex('ffffffffffffffffffffffffffffffff')
    }, /Private key must be greater than 0/)
  })

  tape.test('throws if IL is not within interval [1, n - 1] | IL === n', function () {
    this.mock(BigInteger).expects('fromBuffer')
      .once().returns(curve.n)

    t.throws(function () {
      BIP32.fromSeedHex('ffffffffffffffffffffffffffffffff')
    }, /Private key must be less than the curve order/)
  })

  tape.test('throws on low entropy seed', function () {
    t.throws(function () {
      BIP32.fromSeedHex('ffffffffff')
    }, /Seed should be at least 128 bits/)
  })

  tape.test('throws on too high entropy seed', function () {
    t.throws(function () {
      BIP32.fromSeedHex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    }, /Seed should be at most 512 bits/)
  })
})

tape.test('derive', function (t) {
  function verifyVector (hd, v) {
    if (hd.isNeutered()) {
      t.equal(hd.toBase58(), v.base58)
    } else {
      t.equal(hd.neutered().toBase58(), v.base58)
      t.equal(hd.toBase58(), v.base58Priv)
    }

    t.equal(hd.getFingerprint().toString('hex'), v.fingerprint)
    t.equal(hd.getIdentifier().toString('hex'), v.identifier)
    t.equal(hd.getAddress(), v.address)
    t.equal(hd.keyPair.toWIF(), v.wif)
    t.equal(hd.keyPair.getPublicKeyBuffer().toString('hex'), v.pubKey)
    t.equal(hd.chainCode.toString('hex'), v.chainCode)
    t.equal(hd.depth, v.depth >>> 0)
    t.equal(hd.index, v.index >>> 0)
  }

  fixtures.valid.forEach(function (f) {
    var network = NETWORKS[f.network]
    var hd = BIP32.fromSeedHex(f.master.seed, network)
    var master = hd

    // testing deriving path from master
    f.children.forEach(function (c) {
      t.test(c.path + ' from ' + f.master.fingerprint + ' by path', function () {
        var child = master.derivePath(c.path)
        var childNoM = master.derivePath(c.path.slice(2)) // no m/ on path

        verifyVector(child, c)
        verifyVector(childNoM, c)
      })
    })

    // testing deriving path from children
    f.children.forEach(function (c, i) {
      var cn = master.derivePath(c.path)

      f.children.slice(i + 1).forEach(function (cc) {
        t.test(cc.path + ' from ' + c.fingerprint + ' by path', function () {
          var ipath = cc.path.slice(2).spltape.test('/').slice(i + 1).join('/')
          var child = cn.derivePath(ipath)
          verifyVector(child, cc)

          t.throws(function () {
            cn.derivePath('m/' + ipath)
          }, /Not a master node/)
        })
      })
    })

    // FIXME: test data is only testing Private -> private for now
    f.children.forEach(function (c) {
      if (c.m === undefined) return

      tape.test(c.path + ' from ' + f.master.fingerprint, function () {
        if (c.hardened) {
          hd = hd.deriveHardened(c.m)
        } else {
          hd = hd.derive(c.m)
        }

        verifyVector(hd, c)
      })
    })
  })

  tape.test('works for Private -> public (neutered)', function () {
    var f = fixtures.valid[1]
    var c = f.children[0]

    var master = BIP32.fromBase58(f.master.base58Priv, NETWORKS_LIST)
    var child = master.derive(c.m).neutered()

    t.equal(child.toBase58(), c.base58)
  })

  tape.test('works for Private -> public (neutered, hardened)', function () {
    var f = fixtures.valid[0]
    var c = f.children[0]

    var master = BIP32.fromBase58(f.master.base58Priv, NETWORKS_LIST)
    var child = master.deriveHardened(c.m).neutered()

    t.equal(c.base58, child.toBase58())
  })

  tape.test('works for Public -> public', function () {
    var f = fixtures.valid[1]
    var c = f.children[0]

    var master = BIP32.fromBase58(f.master.base58, NETWORKS_LIST)
    var child = master.derive(c.m)

    t.equal(c.base58, child.toBase58())
  })

  tape.test('throws on Public -> public (hardened)', function () {
    var f = fixtures.valid[0]
    var c = f.children[0]

    var master = BIP32.fromBase58(f.master.base58, NETWORKS_LIST)

    t.throws(function () {
      master.deriveHardened(c.m)
    }, /Could not derive hardened child key/)
  })

  tape.test('throws on wrong types', function () {
    var f = fixtures.valid[0]
    var master = BIP32.fromBase58(f.master.base58, NETWORKS_LIST)

    fixtures.invalid.derive.forEach(function (fx) {
      t.throws(function () {
        master.derive(fx)
      }, /Expected UInt32/)
    })

    fixtures.invalid.deriveHardened.forEach(function (fx) {
      t.throws(function () {
        master.deriveHardened(fx)
      }, /Expected UInt31/)
    })

    fixtures.invalid.derivePath.forEach(function (fx) {
      t.throws(function () {
        master.derivePath(fx)
      }, /Expected BIP32 derivation path/)
    })
  })

  tape.test('works when private key has leading zeros', function () {
    var key = 'xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr'
    var hdkey = BIP32.fromBase58(key)
    t.equal(hdkey.keyPair.d.toBuffer(32).toString('hex'), '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd')
    var child = hdkey.derivePath('m/44\'/0\'/0\'/0/0\'')
    t.equal(child.keyPair.d.toBuffer().toString('hex'), '3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb')
  })
})

var hd = BIP32.fromSeed(Buffer.alloc(64))

tape.test('sign', function () {
  this.mock(keyPair).expects('sign')
    .once().withArgs(hash).returns('signed')

  t.equal(hd.sign(hash), 'signed')
})

tape.test('verify', function (t) {
  var signature = hd.sign(hash)

  this.mock(keyPair).expects('verify')
    .once().withArgs(hash, signature).returns('verified')

  t.equal(hd.verify(hash, signature), 'verified')
})

tape.test('fromBase58 / toBase58', function (t) {
  validAll.forEach(function (f) {
    tape.test('exports ' + f.base58 + ' (public) correctly', function () {
      var hd = BIP32.fromBase58(f.base58, NETWORKS_LIST)

      t.throws(function () { hd.keyPair.toWIF() }, /Missing private key/)
    })
  })

  validAll.forEach(function (f) {
    tape.test('exports ' + f.base58Priv + ' (private) correctly', function () {
      var hd = BIP32.fromBase58(f.base58Priv, NETWORKS_LIST)

      t.equal(hd.toBase58(), f.base58Priv)
      t.equal(hd.keyPair.toWIF(), f.wif)
    })
  })

  fixtures.invalid.fromBase58.forEach(function (f) {
    tape.test('throws on ' + f.string, function () {
      t.throws(function () {
        var networks = f.network ? NETWORKS[f.network] : NETWORKS_LIST

        BIP32.fromBase58(f.string, networks)
      }, new RegExp(f.exception))
    })
  })
})
*/
