# fastify-jwt-webapp  
  
*fastify-jwt-webapp* brings the security and simplicity of JSON Web Tokens to your [Fastify][fastify]-based web apps.  This plugin assumes does not assume your knowledge of JWTs themselves, but knowledge of the workflows involved, particularly as it relates to *your* provider, are assumed.  
  
To see *fastify-jwt-webapp* in the wild check out [my website](https://www.charlesread.io).  
  
[fastify]: https://fastify.io/

<!-- toc -->

- [Example](#example)
  * [index.js](#indexjs)
  * [config.js](#configjs)
- [Cookie](#cookie)
- [Refresh Tokens](#refresh-tokens)
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
  
Being "logged-in" is achieved by passing along the JWT along with each request, as is typical with APIs (via the `Authorization` header). *fastify-jwt-webapp* does this by storing the JWT in a cookie (`options.cookie.name`, "token" by default).  By default this cookie is `Secure`, meaning that it will only be sent by the browser back to your app if the connection is secure.  To change this behavior set `options.cookie.secure` to `false`.  DO NOT DO THIS IN PRODUCTION.  YOU HAVE BEEN WARNED.  To see cookie options please see `lib/config.js`.
  
## Refresh Tokens  
  
This plugin does not treat refresh tokens, but there's no reason that you couldn't implement this functionality yourself. #sorrynotsorry  
  
## Options  
  
| Key |   | Default | Description |
| --- | --- | --- | --- |
| service | _required_  | `auth0` | This plugin makes use of "templates" that control the parameters that are sent to the IdP.  Can be `auth0` or `o365` right now. |
| client_id | _required_ |  | Your client ID. |
| client_secret | _required_ |  | You client secret. |
| urlAuthorize | _required_ |  | The URL that your IdP uses for login, `https://yourinstance.auth0.com/authorize`, for example. |
| urlToken | _required_ |  | The URL that your IdP uses for exchanging an `authorization_code` for access token(s), in this case a JWT, `https://yourinstance.auth0.com/oauth/token`, for example. |
| urlJWKS | _required_ |  | The URL that serves your JWKS, `https://yourinstance.auth0.com/.well-known/jwks.json`, for example. |
| redirect_uri | _required_ |  | This is the URL to which an IdP should redirect in order to process the successful authentication, `https://myapp.example.com/callback`, for example. |
| pathCallback |  | `/callback` | `fastify-jwt-webapp` creates several endpoints in your application, this is one of them, it processes the stuff that your IdP sends over after successful authentication, by default the endpoint is `/callback`, but you can change that with this parameter.  This is very related to the `redirect_uri` option mentioned above. |
| pathLogin |  | `/login` | This is the second endpoint that `fastify-jwt-webapp` adds, it redirects to `urlAuthorize` (with some other stuff along the way), it's `/login` by default, but you can change it to anything, it's just aesthetic. |
| pathSuccessRedirect |  | `/` | Where do you get redirected after successful authentication?  `pathSuccessRedirect`, that's where. |
| pathExempt |   | `['/login', '/callback']` | An array of endpoint paths to be excluded from the actions of the plugin (unauthenticated routes). |
| nameCredentialsDecorator |  | `credentials` | After successful authentication, the fastify request object will be decorated with the payload of the JWT, you can control that decorator here, `req.theLoggedInUsersInfo` for example. |