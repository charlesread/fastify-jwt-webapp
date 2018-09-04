'use strict'

// native Node modules
const path = require('path')
const URL = require('url').URL

// npm modules
const jwksClient = require('jwks-rsa')
const jsonwebtoken = require('jsonwebtoken')
const fp = require('fastify-plugin')
const request = require('request')

// custom modules
const config = require(path.join(__dirname, 'lib', 'config.js'))

let log
let client

const functionGetJWT = function (_authorizationCode) {
  log.trace('functionGetJWT was invoked')
  return new Promise(function (resolve, reject) {
    const requestObject = config.generateTokenRequestObject(_authorizationCode)
    console.log(requestObject)
    request(requestObject, function (err, response, body) {
      if (err) {
        return reject(err)
      }
      log.trace('functionGetJWT was successful, body: %j', body)
      return resolve(body)
    })
  })
}

const getKey = function (header, callback) {
  log.trace('getKey was invoked')
  client.getSigningKey(header.kid, function (err, key) {
    if (err) return callback(err, null)
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey)
  })
}

const implementation = function (fastify, options, next) {

  const _config = config.init(options)

  log = fastify.log.child({module: 'fjwt'})

  try {

    client = jwksClient({
      jwksUri: _config.urlJWKS
    })

    // register cookie plugin so that we can persist the JWT from request to request
    fastify.register(require('fastify-cookie'), function (err) {
      if (err) return next(new Error(`there was an error registering fastify-cookie: ${err.message}`))
    })

    // endpoint for logging in
    fastify.get(_config.pathLogin, async function (req, reply) {
      log.trace('%s was invoked', _config.pathLogin)
      const authorozationUrl = config.generateAuthorizationUrl()
      log.trace('generated authorizationUrl: %s', authorozationUrl)
      // redirect to authentication provider (like Auth0)
      return reply.redirect(authorozationUrl)
    })

    // callback endpoint that will be redirected to once successfully authenticated with the authentication provider
    // this endpoint will convert the authorization code to a JWT and set a cookie with the JWT
    fastify.get(_config.pathCallback, async function (req, reply) {
      log.trace(`callback endpoint requested, code: ${req.query.code}`)
      const jwtResponse = await functionGetJWT(req.query.code, _config)
      fastify.log.debug('jwtResponse: %o', jwtResponse)
      const token = jwtResponse.id_token
      fastify.log.debug(`token: ${token}`)
      if (_config.authorizationCallback) {
        try {
          await _config.authorizationCallback(jwtResponse, req, reply)
        } catch (err) {
          fastify.log.warn(err.message)
        }
      }
      return reply
        .setCookie(_config.cookie.name, token, _config.cookie)
        .redirect(_config.pathSuccessRedirect)
    })

    fastify.decorateRequest(_config.nameCredentialsDecorator, undefined)

    fastify.addHook('preHandler', function (req, reply, next) {
      try {
        log.trace('fastify-jwt-webapp preHandler hook invoked')
        const originalUrl = (new URL(`http://dummy.com${req.raw.originalUrl}`)).pathname
        log.trace('originalUrl: %s', originalUrl)
        // let the request through if it's exempt
        const token = req.cookies[_config.cookie.name]
        if (token) {
          log.trace(`a token exists: ${token}`)
          jsonwebtoken.verify(token, getKey, function (err, decodedToken) {
            if (err) {
              log.trace('token verification was not successful: %j', err.message)
              if (!_config.pathExempt.includes(originalUrl)) {
                log.trace(`pathExempt does NOT include ${originalUrl}, redirecting to ${_config.urlLogin}`)
                return reply.redirect(config.generateAuthorizationUrl())
              }
              log.trace(`pathExempt DOES include ${originalUrl}`)
              return next()
            }
            log.trace('verification was successful, decodedToken: %j', decodedToken)
            req[_config.nameCredentialsDecorator] = decodedToken
            return next()
          })
        } else {
          log.trace('a token does not exist')
          if (!_config.pathExempt.includes(originalUrl)) {
            log.trace(`pathExempt does NOT include ${originalUrl}, redirecting to ${_config.urlLogin}`)
            return reply.redirect(config.generateAuthorizationUrl())
          }
          log.trace(`pathExempt DOES include ${originalUrl}`)
          return next()
        }
      } catch (e) {
        next(e)
      }
    })

  } catch (e) {
    next(e)
  }

  next()
}

module.exports = fp(implementation, {
  fastify: '1.x'
})