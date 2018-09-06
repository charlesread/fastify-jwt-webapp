'use strict'

const tap = require('tap')
const Fastify = require('fastify')

const plugin = require('../plugin')

function buildFastify(_pluginOptions) {
  const f = Fastify()
  f.register(plugin, _pluginOptions)
  tap.teardown(f.close)
  return f
}

let f = buildFastify({})

f.listen(3000, function (err) {
  tap.ok(err, 'should throw an error when config option is incomplete')
  f.close(tap.error)
})