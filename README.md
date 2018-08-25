# fastify-jwt-webapp

*fastify-jwt-webapp* brings the security and simplicity of JSON Web Tokens to your [Fastify][fastify]-based web apps.  This plugin assumes does not assume your knowledge of JWTs themselves, but knowledge of the workflows involved, particularly as it relates to *your* provider, are assumed.

To see *fastify-jwt-webapp* in the wild check out [my website](https://www.charlesread.io).

[fastify]: https://fastify.io/

<!-- toc -->

- [Example](#example)
- [Cookie](#cookie)

<!-- tocstop -->

## Example
```bash
npm install --save fastify-jwt-webapp
```
```javascript
'use strict'  
  
const fastify = require('fastify')()  
  
const fjwt = require('fastify-jwt-webapp')  
  
!async function () {  
  await fastify.register(require('fastify-tls-keygen'))
  await fastify.register(fjwt, {  
    urlLogin: 'https://yourface.auth0.com/authorize',  
	urlAuthorizationCode: 'https://yourface.auth0.com/oauth/token',  
    urlJWKS: 'https://yourface.auth0.com/.well-known/jwks.json',  
    client_id: 'your client_id',  
    client_secret: 'your client_secret',  
    redirect_uri: 'http://localhost:3000/callback'  
  })  
  fastify.get('/', async function (req, reply) {  
    reply.send(req.credentials)  
  })
  await fastify.listen(8443)  
}()  
  .catch(function (err) {  
    console.error(err.message)  
  })
```

## Cookie

Being "logged-in" is achieved by passing along the JWT along with each request, as is typical with APIs (via the `Authorization` header). *fastify-jwt-webapp* does this by storing the JWT in a cookie (`options.cookie.name`, "token" by default).  By default this cookie is `Secure`, meaning that it will only be sent by the browser back to your app if the connection is secure.  To change this behavior set `options.cookie.secure` to `false`.  DO NOT DO THIS IN PRODUCTION.  YOU HAVE BEEN WARNED.