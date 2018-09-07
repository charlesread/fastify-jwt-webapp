'use strict'

const tap = require('tap')
const Fastify = require('fastify')
const nock = require('nock')

const plugin = require('../plugin')

const configs = {
  bad: {},
  good: {
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com'
  }
}

function buildFastify(_pluginOptions) {
  const f = Fastify({
    logger: {
      level: 'trace',
      stream: process.stdout
    }
  })
  f.register(plugin, _pluginOptions)
  return f
}

tap.test('should throw when config option is incomplete', function (t) {
  t.plan(2)
  let f = buildFastify(configs.bad)
  f.listen(3000, function (err) {
    t.ok(err)
    f.close(t.error)
  })
})

tap.test('should not complain when input values are not terrible', async function (t) {
  t.plan(0)
  let f = buildFastify(configs.good)
  f.get('/', (req, reply) => {reply.send('/')})
  await f.listen(3000)
  f.close(t.end)
})

tap.test('/login should redirect to urlAuthorize', async function (t) {
  t.plan(2)
  let f = buildFastify(configs.good)
  await f.listen(3000)
  const response = await f.inject({
    method: 'GET',
    url: '/login'
  })
  t.equal(response.statusCode, 302)
  t.equal(response.headers.location, 'http://www.example.com/?response_type=code&scope=openid&client_id=abc&redirect_uri=http%3A%2F%2Fwww.example.com')
  f.close(t.end)
})

tap.test('/callback should work', async function (t) {
  t.plan(0)
  nock(configs.good.urlToken)
    .post('/')
    .reply(200, {
      id_token: 'blah'
    })
  nock(configs.good.urlToken)
    .post('/')
    .reply(200, {
      id_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM'
    })

  let f = buildFastify(configs.good)
  await f.listen(3000)
  await f.inject({
    method: 'GET',
    url: '/callback?code=123'
  })
  // t.equal(response.statusCode, 302)
  // t.equal(response.headers.location, 'http://www.example.com/?response_type=code&scope=openid&client_id=abc&redirect_uri=http%3A%2F%2Fwww.example.com')
  f.close(t.end)
})

