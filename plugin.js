'use strict'

// native Node modules
const path = require('path')
const URL = require('url').URL

// npm modules
const fp = require('fastify-plugin')

// custom modules
const configFactory = require(path.join(__dirname, 'lib', 'config.js'))

const implementation = async function (fastify, options) {

  const config = configFactory(options)
  const _config = config.get()
  const log = fastify.log.child({module: 'fastify-jwt-webapp'})

  // register cookie plugin so that we can persist the JWT from request to request
  fastify.register(require('fastify-cookie'))

  // endpoint for logging in
  fastify.get(_config.pathLogin, async function (req, reply) {
    log.debug('%s was invoked', _config.pathLogin)
    const authorizationUrl = config.generateAuthorizationUrl()
    log.debug('generated authorizationUrl: %s', authorizationUrl)
    // redirect to authentication provider (like Auth0)
    return reply.redirect(authorizationUrl)
  })

  // callback endpoint that will be redirected to once successfully authenticated with the authentication provider
  // this endpoint will convert the authorization code to a JWT and set a cookie with the JWT
  fastify.get(_config.pathCallback, async function (req, reply) {
    log.debug(`fastify-jwt-webapp callback endpoint ${_config.pathCallback} requested`)
    // trade the auth code for a JWT
    log.debug(`exchanging ${req.query.code} for a JWT`)
    const jwtResponse = await config.functionGetJWT(req.query.code)
    log.debug('functionGetJWT invoked, response: %o', jwtResponse)
    // pull out the actual JWT from the response
    const token = jwtResponse[_config.nameTokenAttribute]
    log.debug(`token received from functionGetJWT: ${token}`)
    if (token) {
      log.debug('the token exists')
      let decodedToken
      try {
        log.debug(`attempting to verify the token`)
        decodedToken = await config.verifyJWT(token)
        log.debug('the token was successfully decoded: %o', decodedToken)
        // call the user-defined callback upon successful authentication, totally optional
        if (_config.authorizationCallback) {
          log.debug('authorizationCallback was specified')
          try {
            await _config.authorizationCallback(jwtResponse, req, reply)
          } catch (err) {
            log.warn(err.message)
          }
        }
        log.debug('setting cookie "%s" to a value of "%s", with these attributes: %o', _config.cookie.name, token, _config.cookie)
        return reply
          .setCookie(_config.cookie.name, token, _config.cookie)
          .redirect(_config.pathSuccessRedirect)
      } catch (err) {
        log.warn('the token was not successfully verified, no cookie will be set: %s', err.message)
        return reply
          .redirect(_config.pathLogin)
      }
    } else {
      log.debug('the token does not exists')
      throw new Error('authorization code could not be exchanged for a JWT')
    }
  })

  fastify.decorateRequest(_config.nameCredentialsDecorator, undefined)

  fastify.addHook('preHandler', async function (req, reply) {
    log.debug('fastify-jwt-webapp preHandler hook invoked')
    const originalUrl = (new URL(`http://dummy.com${req.raw.originalUrl}`)).pathname
    log.debug('originalUrl: %s', originalUrl)
    const token = req.cookies[_config.cookie.name]
    if (token) {
      log.debug(`a token exists in the '${_config.cookie.name}' cookie: ${token}`)
      try {
        const verifiedToken = await config.verifyJWT(token)
        log.debug('token verification was successful, verified token: %j', verifiedToken)
        req[_config.nameCredentialsDecorator] = verifiedToken
      } catch (err) {
        log.debug('token verification was not successful: %j', err.message)
        if (!_config.pathExempt.includes(originalUrl)) {
          log.debug(`pathExempt does NOT include ${originalUrl}, redirecting to ${_config.urlAuthorize}`)
          return reply
            .setCookie(_config.cookie.name, undefined, Object.assign({}, _config.cookie, {expires: ((Date.now()) - 1000)}))
            .redirect(_config.pathLogin)
        } else {
          log.debug(`pathExempt DOES include ${originalUrl}, letting through`)
        }
      }
    } else {
      log.debug('a token does not exist')
      if (!_config.pathExempt.includes(originalUrl)) {
        log.debug(`pathExempt does NOT include ${originalUrl}, redirecting to ${_config.urlAuthorize}`)
        return reply
          .redirect(_config.pathLogin)
      }
      log.debug(`pathExempt DOES include ${originalUrl}, letting through`)
    }
  })

}

module.exports = fp(implementation, {
  fastify: '1.x'
})