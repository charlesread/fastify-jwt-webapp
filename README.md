[![Build Status](https://travis-ci.org/charlesread/fastify-jwt-webapp.svg?branch=master)](https://travis-ci.org/charlesread/fastify-jwt-webapp)
[![Coverage Status](https://coveralls.io/repos/github/charlesread/fastify-jwt-webapp/badge.svg?branch=master)](https://coveralls.io/github/charlesread/fastify-jwt-webapp?branch=master)

# fastify-jwt-webapp  
  
_fastify-jwt-webapp_ brings the security and simplicity of JSON Web Tokens to your [fastify][fastify]-based web apps, single- and multi-paged "traditional" applications are the target of this plugin, although it does not impose a server-side session to accomplish being "logged-in" from request to request.  Rather, a JWT is simply stored in a client-side cookie and retrieved and verified with each request after successful login. This plugin does not assume your knowledge of JWTs themselves, but knowledge of the workflows involved, particularly as it relates to *your* provider, are assumed. (this plugin uses a `/authorize -> authorization_code -> /oauth/token -> JWT`-like workflow) 
  
To see _fastify-jwt-webapp_ in the wild check out [my website](https://www.charlesread.io).  
  
[fastify]: https://fastify.io/

<!-- toc -->

- [Example](#example)
  * [index.js](#indexjs)
  * [config.js](#configjs)
- [Cookie](#cookie)
- [Refresh Tokens](#refresh-tokens)
- [JWKS Caching](#jwks-caching)
- [Options](#options)

<!-- tocstop -->

## Example

```bash  
npm install --save fastify-jwt-webapp
```  
### index.js 

```js
'use strict'

require('pino-pretty')

const fastify = require('fastify')({
  https: true,
  logger: {
    prettyPrint: true,
    level: 'trace'
  }
})

const fjwt = require('fastify-jwt-webapp')

const config = require('./config')

async function main () {
  // just local TLS
  await fastify.register(require('fastify-tls-keygen'))
  // register the plugin and pass config (from examples/config.js)
  await fastify.register(fjwt, config.fjwt)

  // a homepage with a login link
  fastify.get('/', async function (req, reply) {
    reply
      .type('text/html')
      .send('<a href="/login">Click here to log-in</a>')
  })

  // a protected route that will simply display one's credentials
  fastify.get('/credentials', async function (req, reply) {
    reply.send({
      credentials: req.credentials
    })
  })

  await fastify.listen(8443, 'localhost')
}

main()
  .then(function() {
    console.log('server started')
  })
  .catch(function (err) {
    console.error(err.message)
  })
``` 
 
### config.js 

```js
'use strict'

const config = {}

config.fjwt = {
  service: 'auth0',
  urlAuthorize: 'https://instance.auth0.com/authorize',
  urlToken: 'https://instance.auth0.com/oauth/token',
  urlJWKS: 'https://instance.auth0.com/.well-known/jwks.json',
  client_id: '',
  client_secret: '',
  redirect_uri: 'https://localhost:8443/callback',
  // the following is optional
  pathSuccessRedirect: '/credentials', // '/' by default
  pathExempt: [
    '/',
    '/login',
    '/callback'
  ], // ['/login', '/callback'] by default
  authorizationCallback: async function (jwtResponse, req, reply) {
    req.log.info('hello from authorizationCallback!')
    req.log.info('jwtResponse: %o', jwtResponse)
  }
}

module.exports = config

```  
  
## Cookie  
  
Being "logged-in" is achieved by passing along the JWT along with each request, as is typical with APIs (via the `Authorization` header). _fastify-jwt-webapp_ does this by storing the JWT in a cookie (`options.cookie.name`, "token" by default).  By default this cookie is `Secure`, meaning that it will only be sent by the browser back to your app if the connection is secure.  To change this behavior set `options.cookie.secure` to `false`.  DO NOT DO THIS IN PRODUCTION.  YOU HAVE BEEN WARNED.  To see cookie options please see `lib/config.js`.
  
## Refresh Tokens  
  
This plugin does not treat refresh tokens, but there's no reason that you couldn't implement this functionality yourself. #sorrynotsorry  

## JWKS Caching

Fetching the JWKS is by far the most taxing part of this whole process; often making your request 10x slower, that's just the cost of doing business with JWTs in this context because the JWT needs to be verified on each request, and that entails having the public key, thus fetching the JWKS from `options.urlJWKS` on _every single request_.  Fortunately, a JWKS doesn't change particularly frequently, _fastify-jwt-webapp_ can cache the JWKS for `options.cacheJWKSAge` milliseconds, even a value like `10000` (10 seconds) will, in the long-term, add up to much less time spent fetching the JWKS and significantly snappier requests (well, at least until `options.cacheJWKSAge` milliseconds after the caching request, at which point the cache will be refreshed for another `options.cacheJWKSAge` milliseconds).
  
## Options  
  
| Key |   | Default | Description |
| --- | --- | --- | --- |
| `service` | _required_  | `auth0` | This plugin makes use of "templates" that control the parameters that are sent to the IdP.  Can be `auth0` or `o365` right now. |
| `client_id` | _required_ |  | Your client ID. |
| `client_secret` | _required_ |  | You client secret. |
| `urlAuthorize` | _required_ |  | The URL that your IdP uses for login, `https://yourinstance.auth0.com/authorize`, for example. |
| `urlToken` | _required_ |  | The URL that your IdP uses for exchanging an `authorization_code` for access token(s), in this case a JWT, `https://yourinstance.auth0.com/oauth/token`, for example. |
| `urlJWKS` | _required_ |  | The URL that serves your JWKS, `https://yourinstance.auth0.com/.well-known/jwks.json`, for example. |
| `cookie.domain` | _required_ | `os.hostname()` | _fastify-jwt-webapp_ works by setting a cookie, so you need to specify the domain for which the cookie will be sent. |
| `redirect_uri` | _required_ |  | This is the URL to which an IdP should redirect in order to process the successful authentication, `https://myapp.example.com/callback`, for example. |
| `pathCallback` |  | `/callback` | _fastify-jwt-webapp_ creates several endpoints in your application, this is one of them, it processes the stuff that your IdP sends over after successful authentication, by default the endpoint is `/callback`, but you can change that with this parameter.  This is very related to the `redirect_uri` option mentioned above. |
| `pathLogin` |  | `/login` | This is the second endpoint that _fastify-jwt-webapp_ adds, it redirects to `urlAuthorize` (with some other stuff along the way), it's `/login` by default, but you can change it to anything, it's just aesthetic. |
| `pathSuccessRedirect` |  | `/` | Where do you get redirected after successful authentication?  `pathSuccessRedirect`, that's where. |
| `pathExempt` |   | `['/login', '/callback']` | An array of endpoint paths to be excluded from the actions of the plugin (unauthenticated routes). |
| `nameCredentialsDecorator` |  | `credentials` | After successful authentication, the fastify request object will be decorated with the payload of the JWT, you can control that decorator here, `req.theLoggedInUsersInfo` for example. |
| `authorizationCallback` |  |  | `authorizationCallback` is a totally optional function with signature `async function(jwtResponse, request, reply)` that is called after successful authentication, it has absolutely no effect on the plugin's actual functionality. |
| `cacheJWKSAge` | _(disabled)_ |  | Will cache the JWKS for `cacheJWKSAge` milliseconds after the first request that needs it.|
| `redirectOnFail` |  | `false` | If set to `true` the plugin will redirect to `pathLogin` if a JWT is present, but not valid. |