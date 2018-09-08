'use strict'

const tap = require('tap')
const nock = require('nock')

const configFactory = require('../lib/config')

const options = {
  worst: {},
  bad: {
    client_id: 'dsfdsf',
    client_secret: 'sdfsdfsdf'
  },
  almost: {
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'https://charlesread.auth0.com/authorize',
    urlToken: 'https://charlesread.auth0.com/oauth/token',
    urlJWKS: 'not a url',
    redirect_uri: 'https://example.com/callback',
    foo: 'bar'
  },
  good: {
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'https://charlesread.auth0.com/authorize',
    urlToken: 'https://charlesread.auth0.com/oauth/token',
    urlJWKS: 'https://charlesread.auth0.com/blah',
    redirect_uri: 'https://example.com/callback',
    foo: 'bar'
  },
  withService: {
    service: 'o365',
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'https://charlesread.auth0.com/authorize',
    urlToken: 'https://charlesread.auth0.com/oauth/token',
    urlJWKS: 'https://charlesread.auth0.com/blah',
    redirect_uri: 'https://example.com/callback'
  }
}

tap.test('passed options should be valid', function (t) {
  t.plan(4)
  t.throws(function () {
    configFactory(options.worst)
  }, 'throws when options are dumb')
  t.throws(function () {
    configFactory(options.bad)
  }, 'throws when options are kind of dumb')
  t.throws(function () {
    configFactory(options.almost)
  }, 'throws when options are almost good')
  t.doesNotThrow(function () {
    configFactory(options.good)
  }, 'does not throw when options are good')
})

tap.test('generated url and object should be correct', function (t) {
  t.plan(4)
  const config = configFactory(options.good)
  t.equal(
    config.generateAuthorizationUrl(),
    'https://charlesread.auth0.com/authorize?response_type=code&scope=openid&client_id=abc&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback',
    'authorize url generates appropriately'
  )
  const _requestObject = {
    method: 'POST',
    uri: 'https://charlesread.auth0.com/oauth/token',
    json: true,
    body:
      {
        grant_type: 'authorization_code',
        response_mode: 'id_token token',
        client_id: 'abc',
        client_secret: '123',
        redirect_uri: 'https://example.com/callback',
        code: '456'
      }
  }
  t.same(
    config.generateTokenRequestObject('456'),
    _requestObject,
    'request object generates appropriately'
  )
  t.ok(config.generateTokenRequestObject('456').json, 'json is true when auth0')
  const o365Config = configFactory(options.withService)
  t.notOk(o365Config.generateTokenRequestObject('456').json, 'json is false when o365')
})

tap.doesNotThrow(configFactory(options.good).get, 'get() doesn\'t shit the bed')

nock('https://charlesread.auth0.com')
  .post('/oauth/token', configFactory(options.good).generateTokenRequestObject('code').body)
  .reply(200, {
    foo: 'bar'
  })

configFactory(options.good).functionGetJWT('code')
  .then(function (res) {
    tap.same(res, {foo: 'bar'})
  })
