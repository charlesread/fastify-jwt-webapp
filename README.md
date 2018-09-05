# fastify-jwt-webapp

*fastify-jwt-webapp* brings the security and simplicity of JSON Web Tokens to your [Fastify][fastify]-based web apps.  This plugin assumes does not assume your knowledge of JWTs themselves, but knowledge of the workflows involved, particularly as it relates to *your* provider, are assumed.

To see *fastify-jwt-webapp* in the wild check out [my website](https://www.charlesread.io).

[fastify]: https://fastify.io/

<!-- toc -->

- [Example](#example)
  * [index.js](#indexjs)
  * [config.js](#configjs)
- [Cookie](#cookie)

<!-- tocstop -->

## Example
```bash
npm install --save fastify-jwt-webapp
```
### index.js
```javascript
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

!async function () {
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
}()
  .catch(function (err) {
    console.error(err.message)
  })
```
### config.js
```javascript
'use strict'

const config = {}

config.fjwt = {
  service: 'auth0',
  urlLogin: 'https://instance.auth0.com/authorize',
  urlAuthorizationCode: 'https://instance.auth0.com/oauth/token',
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

Being "logged-in" is achieved by passing along the JWT along with each request, as is typical with APIs (via the `Authorization` header). *fastify-jwt-webapp* does this by storing the JWT in a cookie (`options.cookie.name`, "token" by default).  By default this cookie is `Secure`, meaning that it will only be sent by the browser back to your app if the connection is secure.  To change this behavior set `options.cookie.secure` to `false`.  DO NOT DO THIS IN PRODUCTION.  YOU HAVE BEEN WARNED.