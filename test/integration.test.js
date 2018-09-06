'use strict'

const tap = require('tap')
const Fastify = require('fastify')

const plugin = require('../plugin')

function buildFastify (_pluginOptions) {
  const f = Fastify()
  f.register(plugin, _pluginOptions)
  tap.teardown(f.close)
  return f
}

tap.test('should throw when config option is incomplete', function (t) {
  t.plan(2)
  let f = buildFastify({})
  f.listen(3000, function (err) {
    t.ok(err)
    f.close(t.error)
  })
})

tap.test('should not complain when input values are not terrible', async function (t) {
  t.plan(0)
  let f = buildFastify({
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com'
  })
  await f.listen(3000)
})
