'use strict'

const URL = require('url').URL
const qs = require('querystring')
const os = require('os')

const deepExtend = require('deep-extend')
const Ajv = require('ajv')
const bajve = require('better-ajv-errors')

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
  pathExempt: [
    '/callback',
    '/login'
  ],
  nameCredentialsDecorator: 'credentials',
  nameTokenAttribute: 'id_token',
  // used as the direct options to fastify-cookie
  cookie: {
    domain: os.hostname(),
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

const optionsSchema = {
  properties: {
    service: {
      type: 'string',
      enum: ['auth0', 'o365']
    },
    client_id: {
      type: 'string'
    },
    client_secret: {
      type: 'string'
    },
    urlAuthorize: {
      type: 'string',
      format: 'uri'
    },
    urlToken: {
      type: 'string',
      format: 'uri'
    },
    urlJWKS: {
      type: 'string',
      format: 'uri'
    },
    redirect_uri: {
      type: 'string',
      format: 'uri'
    }
  },
  required: [
    'client_id',
    'client_secret',
    'urlAuthorize',
    'urlToken',
    'urlJWKS',
    'redirect_uri'
  ]
}

const ajv = new Ajv({jsonPointers: true})
const validate = ajv.compile(optionsSchema)

function factory(_options) {

  const valid = validate(_options)
  if (!valid) {
    // nice error string for AJV errors
    const betterError = bajve(optionsSchema, _options, validate.errors, {format: 'js'})[0].error
    throw new Error(betterError)
  }

  const implementation = {}
  const config = deepExtend({}, defaultConfig, _options)
  config.serviceAttributes = config.serviceAttributes || defaultServiceAttributes[config.service]

  implementation.generateAuthorizationUrl = function () {
    const authorizationUrl = new URL(config.urlAuthorize)
    let queryStringObject = Object.assign({}, config.serviceAttributes.authorization)
    queryStringObject.client_id = config.client_id
    queryStringObject.redirect_uri = config.redirect_uri
    authorizationUrl.search = qs.stringify(queryStringObject)
    return authorizationUrl.toString()
  }

  implementation.generateTokenRequestObject = function (_authorizationCode) {
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

  implementation.get = function () {
    return config
  }

  return implementation

}

module.exports = factory