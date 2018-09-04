'use strict'

const URL = require('url').URL
const qs = require('querystring')

const deepExtend = require('deep-extend')

let config

const defaultConfig = {
  // overall
  client_id: '',
  client_secret: '',
  urlLogin: '',
  urlJWKS: '',
  redirect_uri: '',
  // configurations
  pathLogin: '/login',
  pathCallback: '/callback',
  pathSuccessRedirect: '/',
  pathExempt: [],
  nameCredentialsDecorator: 'credentials',
  // used as the direct options to fastify-cookie
  cookie: {
    domain: 'localhost',
    path: '/',
    // add JWT expiration to current time
    expires: ((Math.floor((Date.now()) / 1000)) + 86400) * 1000,
    httpOnly: true,
    sameSite: 'lax',
    name: 'token',
    secure: true
  }
}

const defaultServiceAttributes = {
  auth0: {
    authorization: {
      response_type: 'code',
      scope: 'openid'
    },
    token: {
      grant_type: 'authorization_code',
      response_mode: 'id_token token'
    }
  },
  ms: {
    authorization: {
      response_mode: 'query',
      scope: 'openid'
    },
    token: {
      response_mode: 'token id_token',
      grant_type: 'authorization_code'
    }
  }
}

defaultConfig.pathExempt = [defaultConfig.pathLogin, defaultConfig.pathCallback, defaultConfig.pathSuccessRedirect]

module.exports = {
  init: function (_opts) {
    config = deepExtend({}, defaultConfig, _opts)
    config.serviceAttributes = config.serviceAttributes || defaultServiceAttributes[_opts.service || 'auth0']
    return config
  },
  generateAuthorizationUrl: function () {
    const authorizationUrl = new URL(config.urlLogin)
    let queryStringObject = Object.assign({}, config.serviceAttributes.authorization)
    queryStringObject.client_id = config.client_id
    queryStringObject.redirect_uri = config.redirect_uri
    authorizationUrl.search = qs.stringify(queryStringObject)
    return authorizationUrl.toString()
  },
  generateTokenRequestObject: function (_authorizationCode) {
    let descriminator = ''
    let requestObject = {}
    if (config.service === 'auth0') {
      descriminator = 'body'
      requestObject.json = true
    }
    if (config.service === 'ms') {
      descriminator = 'form'
    }
    requestObject.method = 'POST'
    requestObject.uri = config.urlAuthorizationCode
    requestObject[descriminator] = Object.assign({}, config.serviceAttributes.token)
    requestObject[descriminator].client_id = config.client_id
    requestObject[descriminator].client_secret = config.client_secret
    requestObject[descriminator].redirect_uri = config.redirect_uri
    requestObject[descriminator].code = _authorizationCode
    requestObject[descriminator].response_mode = config.serviceAttributes.token.response_mode
    return requestObject
  }
}