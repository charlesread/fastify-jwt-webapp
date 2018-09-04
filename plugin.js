'use strict'

const URL = require('url').URL
const qs = require('querystring')

const deepExtend = require('deep-extend')
const jwksClient = require('jwks-rsa')
const jsonwebtoken = require('jsonwebtoken')

const fp = require('fastify-plugin')
const request = require('request')

let log

const defaultOptions = {
  // overall
  client_id: '',
  client_secret: '',
  urlLogin: '',
  urlJWKS: '',
  redirect_uri: '',
  // configurations
  pathLogin: '/login',
  pathCallback: '/callback',
  pathExempt: ['/login', '/callback'],
  pathSuccessRedirect: '/',
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
  },
  // used in building the URL to the auth service
  authorization: {
    response_type: 'code',
    response_mode: 'query',
    scope: 'openid'
  },
  // used to request token from auth service from authorization code
  token: {
    response_mode: 'token id_token',
    grant_type: 'authorization_code',
    resource: '9234c699-c34c-4025-972f-0025d8f21641'
  }
}

let derivedOptions
let client

const getKey = function (header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) return callback(err, null)
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey)
  })
}

const generateAuthorizationUrl = function (_opts) {
  const authorizationUrl = new URL(derivedOptions.urlLogin)
  authorizationUrl.search = qs.stringify({
    client_id: derivedOptions.client_id,
    response_type: derivedOptions.authorization.response_type,
    redirect_uri: derivedOptions.redirect_uri,
    response_mode: derivedOptions.authorization.response_mode
  })
  return authorizationUrl.toString()
}

const functionGetJWT = function (_authorizationCode, _opts) {
  log.trace('functionGetJWT was invoked')
  return new Promise(function (resolve, reject) {
    request({
      method: 'POST',
      uri: _opts.urlAuthorizationCode,
      // json: true,
      // querystring: {
      //   grant_type: 'authorization_code',
      //   client_id: _opts.client_id,
      //   client_secret: _opts.client_secret,
      //   code: _authorizationCode,
      //   redirect_uri: _opts.redirect_uri,
      //   response_mode: 'id_token token'
      // },
      // body: {
      //   grant_type: 'authorization_code',
      //   client_id: _opts.client_id,
      //   client_secret: _opts.client_secret,
      //   code: _authorizationCode,
      //   redirect_uri: _opts.redirect_uri,
      //   response_mode: 'id_token token'
      // },
      form: {
        grant_type: derivedOptions.token.grant_type,
        client_id: derivedOptions.client_id,
        client_secret: derivedOptions.client_secret,
        code: _authorizationCode,
        redirect_uri: derivedOptions.redirect_uri,
        response_mode: derivedOptions.token.response_mode,
        resource: derivedOptions.token.resource
      }
    }, function (err, response, body) {
      if (err) {
        return reject(err)
      }
      log.trace('functionGetJWT was successful, body: %j', body)
      try {
        body = JSON.parse(body)
      } catch (e) {
      }
      return resolve(body)
    })
  })
}

const implementation = function (fastify, options, next) {

  log = fastify.log

  try {

    // merge parameter options with default options
    derivedOptions = deepExtend({}, defaultOptions, options)

    client = jwksClient({
      jwksUri: derivedOptions.urlJWKS
    })

    // register cookie plugin so that we can persist the JWT from request to request
    fastify.register(require('fastify-cookie'), function (err) {
      if (err) return next(new Error(`there was an error registering fastify-cookie: ${err.message}`))
    })

    // endpoint for logging in
    fastify.get(derivedOptions.pathLogin, async function (req, reply) {
      // redirect to authentication provider (like Auth0)
      return reply.redirect(generateAuthorizationUrl(derivedOptions))
    })

    // callback endpoint that will be redirected to once successfully authenticated with the authentication provider
    // this endpoint will convert the authorization code to a JWT and set a cookie with the JWT
    fastify.get(derivedOptions.pathCallback, async function (req, reply) {
      log.trace(`callback endpoint requested, code: ${req.query.code}`)
      const jwtResponse = await functionGetJWT(req.query.code, derivedOptions)
      fastify.log.debug('jwtResponse: %o', jwtResponse)
      const token = jwtResponse.id_token
      fastify.log.debug(`token: ${token}`)
      if (derivedOptions.authorizationCallback) {
        try {
          await derivedOptions.authorizationCallback(jwtResponse, req, reply)
        } catch (err) {
          fastify.log.warn(err.message)
        }
      }
      return reply
        .setCookie(derivedOptions.cookie.name, token, derivedOptions.cookie)
        .redirect(derivedOptions.pathSuccessRedirect)
    })

    fastify.decorateRequest(derivedOptions.nameCredentialsDecorator, undefined)

    fastify.addHook('preHandler', function (req, reply, next) {
      try {
        log.trace('fastify-jwt-webapp preHandler hook invoked')
        const originalUrl = (new URL(`http://dummy.com${req.raw.originalUrl}`)).pathname
        log.trace(`originalUrl: ${originalUrl}`)
        // let the request through if it's exempt
        const token = req.cookies[derivedOptions.cookie.name]
        if (token) {
          log.trace(`a token exists: ${token}`)
          jsonwebtoken.verify(token, getKey, function (err, decodedToken) {
            if (err) {
              log.trace('token verification was not successful: %j', err.message)
              if (!derivedOptions.pathExempt.includes(originalUrl)) {
                log.trace(`pathExempt does NOT include ${originalUrl}, redirecting to ${derivedOptions.urlLogin}`)
                return reply.redirect(generateAuthorizationUrl(derivedOptions))
              }
              log.trace(`pathExempt DOES include ${originalUrl}`)
              return next()
            }
            log.trace('verification was successful, decodedToken: %j', decodedToken)
            req[derivedOptions.nameCredentialsDecorator] = decodedToken
            return next()
          })
        } else {
          log.trace('a token does not exist')
          if (!derivedOptions.pathExempt.includes(originalUrl)) {
            log.trace(`pathExempt does NOT include ${originalUrl}, redirecting to ${derivedOptions.urlLogin}`)
            return reply.redirect(generateAuthorizationUrl(derivedOptions))
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