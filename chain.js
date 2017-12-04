let base58check = require('bs58check')
let crypto = require('./crypto')

function DEFAULT_ADDRESS_FUNCTION (node) {
  return crypto.hash160(node.getPublicKeyBuffer())
}

function Chain (parent, k, addressFunction) {
  k = k || 0
  this.__parent = parent

  this.addresses = []
  this.addressFunction = addressFunction || DEFAULT_ADDRESS_FUNCTION
  this.k = k
  this.map = {}
}

Chain.prototype.__initialize = function () {
  let address = this.addressFunction(this.__parent.derive(this.k))
  this.map[address] = this.k
  this.addresses.push(address)
}

Chain.prototype.clone = function () {
  let chain = new Chain(this.__parent, this.k, this.addressFunction)

  chain.addresses = this.addresses.concat()
  for (let s in this.map) chain.map[s] = this.map[s]

  return chain
}

Chain.prototype.derive = function (address, parent) {
  let k = this.map[address]
  if (k === undefined) return

  parent = parent || this.__parent
  return parent.derive(k)
}

Chain.prototype.find = function (address) {
  return this.map[address]
}

Chain.prototype.get = function () {
  if (this.addresses.length === 0) this.__initialize()

  return this.addresses[this.addresses.length - 1]
}

Chain.prototype.getAll = function () {
  if (this.addresses.length === 0) this.__initialize()

  return this.addresses
}

Chain.prototype.getParent = function () {
  return this.__parent
}

Chain.prototype.next = function () {
  if (this.addresses.length === 0) this.__initialize()
  let address = this.addressFunction(this.__parent.derive(this.k + 1))

  this.k += 1
  this.map[address] = this.k
  this.addresses.push(address)

  return address
}

Chain.prototype.pop = function () {
  let address = this.addresses.pop()
  delete this.map[address]
  this.k -= 1

  return address
}

module.exports = Chain
