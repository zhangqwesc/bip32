let bitcoinjs = require('bitcoinjs-lib')
let Chain = require('../chain')
let discovery = require('../discovery')
let test = require('tape')

let fixtures = require('./fixtures/discovery')

fixtures.valid.forEach(function (f) {
  let network = bitcoinjs.networks[f.network]
  let external = bitcoinjs.HDNode.fromBase58(f.external, network)
  let chain = new Chain(external, f.k)

  test('discovers until ' + f.expected.used + ' for ' + f.description + ' (GAP_LIMIT = ' + f.gapLimit + ')', function (t) {
    discovery(chain, f.gapLimit, function (addresses, callback) {
      return callback(null, f.used)
    }, function (err, used, checked) {
      t.plan(4)
      t.ifErr(err, 'no error')
      t.equal(used, f.expected.used, 'used as expected')
      t.equal(checked, f.expected.checked, 'checked count as expected')

      let unused = checked - used
      for (let i = 1; i < unused; ++i) chain.pop()

      t.equal(chain.get(), f.expected.nextToUse, 'next address to use matches')
    })
  })

  test('discover calls done on error', function (t) {
    let _err = new Error('e')

    discovery(chain, f.gapLimit, function (addresses, callback) {
      return callback(_err)
    }, function (err) {
      t.plan(1)
      t.equal(_err, err, 'error was returned as expected')
    })
  })
})
