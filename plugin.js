'use strict'

// native Node modules
const path = require('path')
const URL = require('url').URL

// npm modules
const fp = require('fastify-plugin')
const moment = require('moment')
const urlPattern = require('url-pattern')

// custom modules
const configFactory = require(path.join(__dirname, 'lib', 'config.js'))

const implementation = async function (fastify, options) {

  const config = configFactory(options)
  const _config = config.get()
  const log = fastify.log.child({module: 'fastify-jwt-webapp'})

  const urlPatterns = _config.pathExempt.map(function (pathPattern) {
    return new urlPattern(pathPattern)
  })

  function pathMatches(_path) {
    for (let i = 0; i < urlPatterns.length; i++) {
      if (urlPatterns[i].match(_path)) {
        return true
      }
    }
    return false
  }

  function getCookieOptionsForExpiration(_expirationDate) {
    return Object.assign({}, _config.cookie, {expires: new Date(_expirationDate)})
  }

  const _cookieOptions = getCookieOptionsForExpiration(moment().add(1, 'days'))

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

  // endpoint for logging out
  fastify.get(_config.pathLogout, async function (req, reply) {
    log.debug('%s was invoked', _config.pathLogout)
    // const _cookieOptions = getCookieOptionsForExpiration(moment().subtract(1, 'days'))
    log.debug('setting cookie "%s" to a value of "%s", with these attributes: %o', _config.cookie.name, '', _cookieOptions)
    return reply
      .setCookie(_config.cookie.name, '', _cookieOptions)
      .redirect(_config.pathLogoutRedirect)
  })

  // callback endpoint that will be redirected to once successfully authenticated with the authentication provider
  // this endpoint will convert the authorization code to a JWT and set a cookie with the JWT
  fastify.get(_config.pathCallback, async function (req, reply) {
    try {
      log.debug(`fastify-jwt-webapp callback endpoint ${_config.pathCallback} requested`)
      let token
      if (_config.mode === 'id_token') {
        log.debug('id_token mode detected')
        token = req.query.id_token
      } else {
        // trade the auth code for a JWT
        log.debug(`exchanging ${req.query.code} for a JWT`)
        const jwtResponse = await config.functionGetJWT(req.query.code)
        log.debug('functionGetJWT invoked, response: %o', jwtResponse)
        // pull out the actual JWT from the response
        token = jwtResponse[_config.nameTokenAttribute]
      }
      log.debug(`token attained: ${token}`)
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
          log.debug('setting cookie "%s" to a value of "%s", with these attributes: %o', _config.cookie.name, token, _cookieOptions)
          const cookieOriginalPath = req.cookies['originalPath']
          log.debug(`cookieOriginalPath: ${cookieOriginalPath}`)
          let determinedPathSuccessRedirect
          if (!options.pathSuccessRedirect && cookieOriginalPath) {
            log.debug(`pathSuccessRedirect was NOT specified in options, redirecting to the path that was originally requested: ${cookieOriginalPath}`)
            determinedPathSuccessRedirect = cookieOriginalPath
          } else {
            log.debug(`pathSuccessRedirect WAS specified in options, so it takes precedence, redirecting to ${_config.pathSuccessRedirect}`)
            determinedPathSuccessRedirect = _config.pathSuccessRedirect
          }
          return reply
            .setCookie(_config.cookie.name, token, _cookieOptions)
            .redirect(determinedPathSuccessRedirect)
        } catch (err) {
          log.warn('the token was not successfully verified, no cookie will be set, redirecting to %s: %s', _config.pathLogin, err.message)
          return reply
            .redirect(_config.pathLogin)
        }
      } else {
        log.debug('the token does not exists')
        return reply.send(new Error('a token was not detected'))
      }
    } catch (err) {
      const errorString = `a error occurred in ${_config.pathCallback}: ${err.message}`
      log.error(errorString)
      log.debug(err.stack)
      return reply.send(new Error(errorString))
    }
  })

  fastify.decorateRequest(_config.nameCredentialsDecorator, undefined)

  fastify.addHook('preHandler', async function (req, reply) {
    log.debug('fastify-jwt-webapp preHandler hook invoked')
    const originalUrlObject = new URL(`http://dummy.com${req.raw.originalUrl}`)
    const originalUrl = originalUrlObject.pathname
    const originalPath = `${originalUrlObject.pathname}${originalUrlObject.search}`
    log.debug('originalPath: %s', originalPath)
    const token = req.cookies[_config.cookie.name]
    if (token) {
      log.debug(`a token exists in the '${_config.cookie.name}' cookie: ${token}`)
      try {
        let verifiedToken = await config.verifyJWT(token)
        log.debug('token verification was successful, verified token: %j', verifiedToken)
        if (_config.credentialTransformation) {
          verifiedToken = await _config.credentialTransformation(verifiedToken)
        }
        req[_config.nameCredentialsDecorator] = verifiedToken
      } catch (err) {
        log.debug('token verification was not successful: %j', err.message)
        if (!pathMatches(originalUrl)) {
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
      if (!pathMatches(originalUrl)) {
        log.debug(`pathExempt does NOT include ${originalUrl}, redirecting to ${_config.urlAuthorize}`)
        return reply
          .setCookie('originalPath', originalPath, _cookieOptions)
          .redirect(_config.pathLogin)
      }
      log.debug(`pathExempt DOES include ${originalUrl}, letting through`)
    }
  })

}

module.exports = fp(implementation, {
  fastify: '1.x'
})