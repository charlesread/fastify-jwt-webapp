'use strict'

const tap = require('tap')

let config = require('../lib/config')

tap.pass('this is fine')

let _config = config.init({
  client_id: 'abc',
  client_secret: '123',
  urlAuthorize: 'https://charlesread.auth0.com/authorize',
  urlToken: 'https://charlesread.auth0.com/oauth/token',
  redirect_uri: 'https://example.com/callback',
  foo: 'bar'
})

tap.equal(_config.foo, 'bar')
tap.equal(_config.pathCallback, '/callback')
tap.equal(_config.serviceAttributes.authorization.scope, 'openid')

tap.equal(config.generateAuthorizationUrl(), 'https://charlesread.auth0.com/authorize?response_type=code&scope=openid&client_id=abc&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback')

let requestObject = config.generateTokenRequestObject('456')

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

tap.ok(requestObject.json)

tap.same(requestObject, _requestObject)

_config = config.init({
  service: 'o365',
  client_id: 'abc',
  client_secret: '123',
  urlAuthorize: 'https://charlesread.auth0.com/authorize',
  urlToken: 'https://charlesread.auth0.com/oauth/token',
  redirect_uri: 'https://example.com/callback',
  foo: 'bar'
})

requestObject = config.generateTokenRequestObject('456')

tap.notOk(requestObject.json)

tap.same(config.get(), _config)