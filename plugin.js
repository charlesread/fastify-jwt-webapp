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

    function pathExempt(_path) {
        for (let i = 0; i < urlPatterns.length; i++) {
            if (urlPatterns[i].match(_path)) {
                return true
            }
        }
        return false
    }

    function getCookieOptionsForExpiration(_expirationDate) {
        log.debug(`_expirationDate passed getCookieOptionsForExpiration to: ${_expirationDate}`)
        return Object.assign({}, _config.cookie, {expires: new Date(_expirationDate)})
    }

    // const _cookieOptions = getCookieOptionsForExpiration(moment().add(1, 'days'))

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
        const _cookieOptions = Object.assign({}, _config.cookie, {expires: new Date(moment().subtract(1, 'days'))})
        delete _cookieOptions.maxAge
        log.debug('setting cookie "%s" to a value of "%s", with these attributes: %o', _config.cookie.name, '', _cookieOptions)
        return reply
            .setCookie(_config.cookie.name, '', _cookieOptions)
            .redirect(_config.pathLogoutRedirect)
    })

    // callback endpoint that will be redirected to once successfully authenticated with the authentication provider
    // this endpoint will convert the authorization code to a JWT and set a cookie with the JWT
    fastify.get(_config.pathCallback, async function (req, reply) {
        log.debug(`fastify-jwt-webapp callback handler for "${_config.pathCallback}" invoked`)
        try {
            const queryError = req.query.error
            if (queryError) {
                log.error(`problem with provider: ${queryError}`)
                return reply
                    .redirect(_config.pathLogin)
            }
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
            if (token) {
                log.debug(`token attained: ${token}`)
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

        const queryError = req.query.error
        if (queryError) {
            log.error(`problem with provider: ${queryError}`)
            return reply
                .redirect(_config.pathLogin)
        }

        const requestedUrlObject = new URL(`http://dummy.com${req.raw.originalUrl}`)
        const requestedPathname = requestedUrlObject.pathname
        const requestedPath = `${requestedUrlObject.pathname}${requestedUrlObject.search}`
        log.debug('requestedPath: %s', requestedPath)

        const token = req.cookies[_config.cookie.name]
        if (token) {
            // if a token exists first determine if it's valid, if it is just let them through to the requested endpoint
            log.debug(`a token exists in the "${_config.cookie.name}" cookie: ${token}`)
            try {
                let verifiedToken = await config.verifyJWT(token)
                log.debug('token verification was successful, verified token: %j', verifiedToken)
                // transform the token if the user has specified a transformation fuction
                if (_config.credentialTransformation) {
                    verifiedToken = await _config.credentialTransformation(verifiedToken)
                }
                // decorate the request with the credentials from token
                req[_config.nameCredentialsDecorator] = verifiedToken
                // token has been verified, no other work is necessary, let user through to requested endpoint
            } catch (err) {
                log.debug('token verification was not successful: %j', err.message)
                if (pathExempt(requestedPathname)) {
                    // a token exists in the cookie, but it isn't valid, and the path is exempt anyway
                    // so let them through to the requested endpoint
                    log.debug(`the token isn't valid, but the path is exempt, letting through...`)
                } else {
                    log.debug(`the token isn't valid, the path is not exempt, killing cookie and redirecting to "${_config.pathLogin}"...`)
                    // kill the cookie, it's not valid
                    const _cookieOptions = Object.assign({}, _config.cookie, {expires: new Date(moment().subtract(1, 'days'))})
                    delete _cookieOptions.maxAge
                    return reply
                        .setCookie(_config.cookie.name, undefined, _cookieOptions)
                        .redirect(_config.pathLogin)
                }
            }
        } else {
            // a token wasn't found in the cookie
            log.debug('a token does not exist')
            if (!pathExempt(requestedPathname)) {
                // the path is not exempt, so redirect to login endpoint
                log.debug(`pathExempt does NOT include ${requestedPathname}, redirecting to "${_config.pathLogin}"`)
                return reply.redirect(_config.pathLogin)
            } else {
                // the path is exempt, so let them through
                log.debug(`pathExempt DOES include ${requestedPathname}, letting through`)
            }
        }

    })

}

module.exports = fp(implementation, {
    fastify: '1.x'
})