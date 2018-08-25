'use strict'

const URL = require('url').URL
const qs = require('querystring')

const deepExtend = require('deep-extend')
const jwksClient = require('jwks-rsa')
const jsonwebtoken = require('jsonwebtoken')

const fp = require('fastify-plugin')
const request = require('request')

const defaultOptions = {
  scope: 'openid',
  pathLogin: '/login',
  pathCallback: '/callback',
  pathExempt: ['/login', '/callback'],
  cookie: {
    domain: 'localhost',
    path: '*',
    // add JWT expiration to current time
    expires: ((Math.floor((Date.now()) / 1000)) + 86400) * 1000,
    httpOnly: true,
    sameSite: 'lax',
    name: 'token',
    secure: true
  },
  nameCredentialsDecorator: 'credentials',
  pathSuccessRedirect: '/'
}

let opts
let client

const getKey = function (header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) return callback(err, null)
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey)
  })
}

const generateAuthorizationUrl = function (_opts) {
  const authorizationUrl = new URL(_opts.urlLogin)
  authorizationUrl.search = qs.stringify({
    response_type: 'code',
    client_id: _opts.client_id,
    redirect_uri: _opts.redirect_uri,
    nonce: Date.now(),
    scope: _opts.scope
  })
  return authorizationUrl.toString()
}

const functionGetJWT = function (_authorizationCode, _opts) {
  return new Promise(function (resolve, reject) {
    request({
      method: 'POST',
      uri: _opts.urlAuthorizationCode,
      json: true,
      body: {
        grant_type: 'authorization_code',
        client_id: _opts.client_id,
        client_secret: _opts.client_secret,
        code: _authorizationCode,
        redirect_uri: _opts.redirect_uri,
        response_mode: 'id_token token'
      }
    }, function (err, response, body) {
      if (err) {
        return reject(err)
      }
      return resolve(body)
    })
  })
}

const implementation = function (fastify, options, next) {

  try {

    // merge parameter options with default options
    opts = deepExtend({}, defaultOptions, options)

    client = jwksClient({
      jwksUri: opts.urlJWKS
    })

    // register cookie plugin so that we can persist the JWT from request to request
    fastify.register(require('fastify-cookie'), function (err) {
      if (err) return next(new Error(`there was an error registering fastify-cookie: ${err.message}`))
    })

    // endpoint for logging in
    fastify.get(opts.pathLogin, async function (req, reply) {
      // redirect to authentication provider (like Auth0)
      return reply.redirect(generateAuthorizationUrl(opts))
    })

    // callback endpoint that will be redirected to once successfully authenticated with the authentication provider
    // this endpoint will convert the authorization code to a JWT and set a cookie with the JWT
    fastify.get(opts.pathCallback, async function (req, reply) {
      const jwtResponse = await functionGetJWT(req.query.code, opts)
      return reply
        .setCookie(opts.cookie.name, jwtResponse.id_token, opts.cookie)
        .redirect(opts.pathSuccessRedirect)
    })

    fastify.decorateRequest(opts.nameCredentialsDecorator, undefined)

    fastify.addHook('preHandler', function (req, reply, next) {
      try {
        const originalUrl = (new URL(`http://dummy.com${req.raw.originalUrl}`)).pathname
        // let the request through if it's exempt
        // if (opts.pathExempt.includes(originalUrl)) return next()
        const token = req.cookies[opts.cookie.name]
        if (token) {
          jsonwebtoken.verify(token, getKey, function (err, decodedToken) {
            if (err) {
              if (!opts.pathExempt.includes(originalUrl)) {
                return reply.redirect(generateAuthorizationUrl(opts))
              }
              next()
            }
            req[opts.nameCredentialsDecorator] = decodedToken
            next()
          })
        } else {
          if (!opts.pathExempt.includes(originalUrl)) {
            return reply.redirect(generateAuthorizationUrl(opts))
          }
          next()
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