# bip32
[![Build Status](https://travis-ci.org/bitcoinjs/bip32.png?branch=master)](https://travis-ci.org/bitcoinjs/bip32)
[![NPM](https://img.shields.io/npm/v/bip32.svg)](https://www.npmjs.org/package/bip32)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)


## Example
``` javascript
let bip32 = require('bip32')
let node =  bip32.fromBase58('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')

let child = node.derivePath('m/0/0')
// ...
```

#### bip32.Account
``` javascript
let bitcoin = require('bitcoinjs-lib')
let bip32 = require('bip32')
let bip39 = require('bip39')

// ...

let mnemonic = bip39.generateMnemonic()
let seed = bip39.mnemonicToSeed(mnemonic)
let account = bip32.Account.standardFromSeed(seed)

console.log(account.getChainAddress(0))
// => 1QEj2WQD9vxTzsGEvnmLpvzeLVrpzyKkGt

account.nextChainAddress(0)

console.log(account.getChainAddress(0))
// => 1DAi282VN7Ack9o5BqWYkiEsS8Vgx1rLn

console.log(account.getChainAddress(1))
// => 1CXKM323V3kkrHmZQYPUTftGh9VrAWuAYX

console.log(account.derive('1QEj2WQD9vxTzsGEvnmLpvzeLVrpzyKkGt'))
// => xpub6A5Fz4JZg4kd8pLTTaMBKsvVgzRBrvai6ChoxWNTtYQ3UDVG1VyAWQqi6SNqkpsfsx9F8pRqwtKUbU4j4gqpuN2gpgQs4DiJxsJQvTjdzfA

// NOTE: passing in the parent nodes allows for private key escalation (see xprv vs xpub)

console.log(account.derive('1QEj2WQD9vxTzsGEvnmLpvzeLVrpzyKkGt', [external, internal]))
// => xprv9vodQPEygdPGUWeKUVNd6M2N533PvEYP21tYxznauyhrYBBCmdKxRJzmnsTsSNqfTJPrDF98GbLCm6xRnjceZ238Qkf5GQGHk79CrFqtG4d
```

##### BIP44
```
// ...

// equivalent to /44'/0'/0'
let account = bip32.Account.bip44FromSeed(seed, 44, 0, 0)

// ...
```


#### bip32.Chain
``` javascript
let bitcoin = require('bitcoinjs-lib')
let bip32 = require('bip32')

// ...

let hdNode = bitcoin.HDNode.fromSeedHex(seedHex)
let chain = new bip32.Chain(hdNode)

for (let k = 0; k < 10; ++k) chain.next()

let address = chain.get()

console.log(chain.find(address))
// => 9

console.log(chain.pop())
// => address
```


#### bip32.discover
``` javascript
```

## LICENSE [ISC](LICENSE)
