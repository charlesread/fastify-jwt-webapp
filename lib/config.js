'use strict'

const URL = require('url').URL
const qs = require('querystring')

const deepExtend = require('deep-extend')

let config

const defaultConfig = {
  // overall
  service: 'auth0',
  client_id: '',
  client_secret: '',
  urlAuthorize: '',
  urlToken: '',
  urlJWKS: '',
  redirect_uri: '',
  // configurations
  pathLogin: '/login',
  pathCallback: '/callback',
  pathSuccessRedirect: '/',
  pathExempt: [],
  nameCredentialsDecorator: 'credentials',
  nameTokenAttribute: 'id_token',
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
    discriminator: 'body',
    authorization: {
      response_type: 'code',
      scope: 'openid'
    },
    token: {
      grant_type: 'authorization_code',
      response_mode: 'id_token token'
    }
  },
  o365: {
    discriminator: 'form',
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

defaultConfig.pathExempt = [defaultConfig.pathLogin, defaultConfig.pathCallback]

module.exports = {
  init: function (_opts) {
    config = deepExtend({}, defaultConfig, _opts)
    config.serviceAttributes = config.serviceAttributes || defaultServiceAttributes[config.service]
    return config
  },
  generateAuthorizationUrl: function () {
    const authorizationUrl = new URL(config.urlAuthorize)
    let queryStringObject = Object.assign({}, config.serviceAttributes.authorization)
    queryStringObject.client_id = config.client_id
    queryStringObject.redirect_uri = config.redirect_uri
    authorizationUrl.search = qs.stringify(queryStringObject)
    return authorizationUrl.toString()
  },
  generateTokenRequestObject: function (_authorizationCode) {
    const requestObject = {
      method: 'POST',
      uri: config.urlToken
    }
    const discriminator = config.serviceAttributes.discriminator
    if (config.serviceAttributes.discriminator.toLowerCase() === 'body') {
      requestObject.json = true
    }
    requestObject[discriminator] = Object.assign({}, config.serviceAttributes.token)
    requestObject[discriminator].client_id = config.client_id
    requestObject[discriminator].client_secret = config.client_secret
    requestObject[discriminator].redirect_uri = config.redirect_uri
    requestObject[discriminator].code = _authorizationCode
    return requestObject
  }
}