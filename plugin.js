'use strict'

// native Node modules
const path = require('path')
const URL = require('url').URL

// npm modules
const fp = require('fastify-plugin')

// custom modules
const config = require(path.join(__dirname, 'lib', 'config.js'))
const util = require(path.join(__dirname, 'lib', 'util.js'))

let log
let _config

const implementation = function (fastify, options, next) {

  _config = config.init(options)
  util.init(config)

  log = fastify.log.child({module: 'fjwt'})

  try {

    // register cookie plugin so that we can persist the JWT from request to request
    fastify.register(require('fastify-cookie'), function (err) {
      if (err) return next(new Error(`there was an error registering fastify-cookie: ${err.message}`))
    })

    // endpoint for logging in
    fastify.get(_config.pathLogin, async function (req, reply) {
      log.trace('%s was invoked', _config.pathLogin)
      const authorizationUrl = config.generateAuthorizationUrl()
      log.trace('generated authorizationUrl: %s', authorizationUrl)
      // redirect to authentication provider (like Auth0)
      return reply.redirect(authorizationUrl)
    })

    // callback endpoint that will be redirected to once successfully authenticated with the authentication provider
    // this endpoint will convert the authorization code to a JWT and set a cookie with the JWT
    fastify.get(_config.pathCallback, async function (req, reply) {
      log.trace(`callback endpoint requested, code: ${req.query.code}`)
      // trade the auth code for a JWT
      const jwtResponse = await util.functionGetJWT(req.query.code, _config)
      log.debug('jwtResponse: %o', jwtResponse)
      // pull out the actual JWT from the response
      const token = jwtResponse[_config.nameTokenAttribute]
      log.debug(`token: ${token}`)
      if (token) {
        let decodedToken
        try {
          decodedToken = await util.verifyJWT(token)
          log.trace('the token was successfully decoded: %o', decodedToken)
          // call the user-defined callback upon successful authentication, totally optional
          if (_config.authorizationCallback) {
            try {
              await _config.authorizationCallback(jwtResponse, req, reply)
            } catch (err) {
              log.warn(err.message)
            }
          }
          return reply
            .setCookie(_config.cookie.name, token, _config.cookie)
            .redirect(_config.pathSuccessRedirect)
        } catch (err) {
          log.warn('the token was not successfully decoded, no cookie will be set: %s', err.message)
          return reply
            .redirect(_config.pathLogin)
        }
      }
    })

    fastify.decorateRequest(_config.nameCredentialsDecorator, undefined)

    fastify.addHook('preHandler', async function (req, reply) {
      log.trace('fastify-jwt-webapp preHandler hook invoked')
      const originalUrl = (new URL(`http://dummy.com${req.raw.originalUrl}`)).pathname
      log.trace('originalUrl: %s', originalUrl)
      const token = req.cookies[_config.cookie.name]
      if (token) {
        log.trace(`a token exists in the '${_config.cookie.name}' cookie: ${token}`)
        try {
          await util.verifyJWT(token)
          log.trace('verification was successful, decodedToken: %j', decodedToken)
          req[_config.nameCredentialsDecorator] = decodedToken
        } catch (err) {
          log.trace('token verification was not successful: %j', err.message)
          if (!_config.pathExempt.includes(originalUrl)) {
            log.trace(`pathExempt does NOT include ${originalUrl}, redirecting to ${_config.urlAuthorize}`)
            return reply.redirect(_config.pathLogin)
          } else {
            log.trace(`pathExempt DOES include ${originalUrl}`)
          }
        }
      } else {
        log.trace('a token does not exist')
        if (!_config.pathExempt.includes(originalUrl)) {
          log.trace(`pathExempt does NOT include ${originalUrl}, redirecting to ${_config.urlAuthorize}`)
          return reply.redirect(_config.pathLogin)
        }
        log.trace(`pathExempt DOES include ${originalUrl}, letting through`)
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