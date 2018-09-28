'use strict'

const URL = require('url').URL
const qs = require('querystring')
const os = require('os')

const deepExtend = require('deep-extend')
const Ajv = require('ajv')
const bajve = require('better-ajv-errors')
const jsonwebtoken = require('jsonwebtoken')
const request = require('request')
const jwksClient = require('jwks-rsa')
const LRU = require('lru-cache')

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
    maxAge: 60 * 60 * 24,
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
      response_type: 'code',
      response_mode: 'query'
    },
    token: {
      grant_type: 'authorization_code',
      resource: ''
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
    },
    cacheJWKSAge: {
      type: 'integer'
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

  if (config.cacheJWKSAge) {
    implementation.cache = LRU()
  }

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

  if (!config.functionGetJWT && config.urlJWKS) {
    implementation.functionGetJWT = function functionGetJWT(_authorizationCode) {
      return new Promise(function (resolve, reject) {
        request(implementation.generateTokenRequestObject(_authorizationCode), function (err, response, body) {
          if (err) return reject(err)
          try {
            body = JSON.parse(body)
          } catch (err) {
          }
          return resolve(body)
        })
      })
    }
  } else {
    implementation.functionGetJWT = config.functionGetJWT
  }

  // if a user has not specified a verifyJWT function use this one, it will attempt to verify a JWT from the
  // JWKS URL, this function also implements rudimentary caching too, for performance
  if (!config.verifyJWT && config.urlJWKS) {
    // resolves the decoded JWT
    const client = jwksClient({
      jwksUri: config.urlJWKS,
      strictSsl: false
    })
    implementation.verifyJWT = function verifyJWT(_token) {
      return new Promise(function (resolve, reject) {
        jsonwebtoken.verify(
          _token,
          // this function just gets the jwks
          function (header, callback) {
            client.getSigningKey(header.kid, function (err, key) {
              if (err) return callback(err, null)
              const signingKey = key.publicKey || key.rsaPublicKey
              callback(null, signingKey)
            })
          },
          function (err, decodedToken) {
            if (err) return reject(err)
            return resolve(decodedToken)
          })
      })
    }
  } else {
    implementation.verifyJWT = config.verifyJWT
  }

  implementation.get = function () {
    return config
  }

  return implementation

}

module.exports = factory