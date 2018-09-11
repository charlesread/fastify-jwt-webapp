'use strict'

const tap = require('tap')
const Fastify = require('fastify')
const rp = require('request-promise')
const request = require('request')

const plugin = require('../plugin')

const configs = {
  bad: {},
  good: {
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com',
    functionGetJWT: async function () {
      return {
        id_token: 'someJWT'
      }
    },
    verifyJWT: function () {
      return {
        sub: 'cread',
        iss: 'dsfd9-0idfk2349089dsahfs98dh'
      }
    },
    authorizationCallback: async function (j, req, reply) {
      return
    }
  }
}

function buildFastify(_pluginOptions) {
  const f = Fastify({
    logger: {
      level: 'trace',
      stream: process.stdout
    }
  })
  f.register(plugin, _pluginOptions)
  return f
}

tap.test('should throw when config option is incomplete', function (t) {
  t.plan(2)
  let f = buildFastify(configs.bad)
  f.listen(3000, function (err) {
    t.ok(err)
    f.close(t.error)
  })
})

tap.test('should not complain when input values are not terrible', async function (t) {
  t.plan(0)
  let f = buildFastify(configs.good)
  f.get('/', (req, reply) => {
    reply.send('/')
  })
  await f.listen(3000)
  f.close(t.end)
})

tap.test('/login should redirect to urlAuthorize', async function (t) {
  t.plan(2)
  let f = buildFastify(configs.good)
  await f.listen(3000)
  const response = await f.inject({
    method: 'GET',
    url: '/login'
  })
  t.equal(response.statusCode, 302)
  t.equal(response.headers.location, 'http://www.example.com/?response_type=code&scope=openid&client_id=abc&redirect_uri=http%3A%2F%2Fwww.example.com')
  f.close(t.end)
})

tap.test('/callback should work when JWT is kosher', async function (t) {
  t.plan(2)
  let f = buildFastify(configs.good)
  await f.listen(3000)
  const response = await f.inject({
    method: 'GET',
    url: '/callback?code=123'
  })
  t.equal(response.statusCode, 302)
  t.equal(response.headers.location, '/')
  f.close(t.end)
})

tap.test('/callback should NOT work when JWT is fubar', async function (t) {
  t.plan(1)
  let f = buildFastify({
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com',
    functionGetJWT: async function () {
      throw new Error('you know what you did')
    }
  })
  await f.listen(3000)
  const response = await f.inject({
    method: 'GET',
    url: '/callback?code=123'
  })
  t.equal(response.statusCode, 500)
  f.close(t.end)
})

tap.test('/callback should work when one can get the JWT but it can not be verified', async function (t) {
  t.plan(2)
  let f = buildFastify({
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com',
    functionGetJWT: async function () {
      return {
        id_token: 'someJWT'
      }
    },
    verifyJWT: function () {
      throw new Error('haha')
    }
  })
  await f.listen(3000)
  const response = await f.inject({
    method: 'GET',
    url: '/callback?code=123'
  })
  t.equal(response.statusCode, 302)
  t.equal(response.headers.location, '/login')
  f.close(t.end)
})

tap.test('/callback should work when the JWT id_token attribute is not found', async function (t) {
  t.plan(1)
  let f = buildFastify({
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com',
    functionGetJWT: async function () {
      return {
        id_tokenz: 'someJWT'
      }
    }
  })
  await f.listen(3000)
  const response = await f.inject({
    method: 'GET',
    url: '/callback?code=123'
  })
  t.equal(response.statusCode, 500)
  f.close(t.end)
})

tap.test('authorizationCallback should warn', async function (t) {
  t.plan(1)
  let f = buildFastify({
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com',
    functionGetJWT: async function () {
      return {
        id_token: 'someJWT'
      }
    },
    verifyJWT: function () {
      return {
        sub: 'cread',
        iss: 'dsfd9-0idfk2349089dsahfs98dh'
      }
    },
    authorizationCallback: async function (j, req, reply) {
      throw new Error('warn')
    }
  })
  await f.listen(3000)
  const response = await f.inject({
    method: 'GET',
    url: '/callback?code=123'
  })
  t.equal(response.statusCode, 302)
  f.close(t.end)
})

tap.test('preHandler shall not falter', async function (t) {
  let response
  t.plan(7)
  let f = buildFastify({
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com',
    functionGetJWT: async function () {
      return {
        id_token: 'someJWT'
      }
    },
    verifyJWT: function () {
      return {
        sub: 'cread',
        iss: 'dsfd9-0idfk2349089dsahfs98dh'
      }
    },
    pathExempt: [
      '/login',
      '/callback',
      '/open'
    ]
  })
  f.get('/open', async (req, reply) => {
    reply.send('open')
  })
  f.get('/closed', async (req, reply) => {
    reply.send('closed')
  })
  response = await f.inject({
    method: 'GET',
    url: '/open'
  })
  t.equal(response.statusCode, 200, '/open should be open')
  response = await f.inject({
    method: 'GET',
    url: '/closed'
  })
  t.equal(response.statusCode, 302, '/closed should be closed')
  await f.listen(3000, '0.0.0.0')
  response = await rp(
    {
      uri: 'http://localhost:3000/closed',
      method: 'GET',
      headers: {
        Cookie: 'token=123456'
      },
      followRedirect: false,
      resolveWithFullResponse: true
    }
  )
  t.equal(response.statusCode, 200, '/closed should be open when valid JWT is passed')
  await f.close()
  //
  //
  //
  f = buildFastify({
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com',
    functionGetJWT: async function () {
      return {
        id_token: 'someJWT'
      }
    },
    verifyJWT: function () {
      throw new Error('shite!')
    },
    pathExempt: [
      '/login',
      '/callback',
      '/open'
    ]
  })
  f.get('/open', async (req, reply) => {
    reply.send('openz')
  })
  await f.listen(3000, '0.0.0.0')
  response = await rp(
    {
      uri: 'http://localhost:3000/open',
      method: 'GET',
      headers: {
        Cookie: 'token=123456'
      },
      followRedirect: false,
      resolveWithFullResponse: true
    }
  )
  t.equal(response.body, 'openz', '/open should return "openz" when JWT is shite but who cares as it is exempt')
  t.equal(response.statusCode, 200, '/closed should return 302 when shite JWT passed')
  await f.close()
  //
  //
  //
  //
  //
  //
  f = buildFastify({
    client_id: 'abc',
    client_secret: '123',
    urlAuthorize: 'http://www.example.com',
    urlToken: 'http://www.example.com',
    urlJWKS: 'http://www.example.com',
    redirect_uri: 'http://www.example.com',
    functionGetJWT: async function () {
      return {
        id_token: 'someJWT'
      }
    },
    verifyJWT: function () {
      throw new Error('shite!')
    },
    pathExempt: [
      '/login',
      '/callback'
    ]
  })
  f.get('/closed', async (req, reply) => {
    reply.send('closed')
  })
  await f.listen(3000, '0.0.0.0')
  const omfgICantBelieveThatIHaveToDoThisShit = function () {
    return new Promise(function (resolve, reject) {
      request(
          {
            uri: 'http://localhost:3000/closed',
            method: 'GET',
            headers: {
              Cookie: 'token=123456'
            },
            followRedirect: false,
            resolveWithFullResponse: true
          },
        function (err, resp, body) {
          if (err) return reject(err)
          return resolve(resp)
        }
      )
    })
  }
  response = await omfgICantBelieveThatIHaveToDoThisShit()
  // response = await rp(
  //   {
  //     uri: 'http://localhost:3000/closed',
  //     method: 'GET',
  //     headers: {
  //       Cookie: 'token=123456'
  //     },
  //     followRedirect: false,
  //     resolveWithFullResponse: true
  //   }
  // )
  // t.equal(response.body, 'openz', '/closed should redirect to /logim when JWT is shite but who cares as it is exempt')
  t.equal(response.headers.location, '/login', '/closed should redirect to /logim when JWT is shite but who cares as it is exempt')
  t.equal(response.statusCode, 302, '/closed should return 302 when shite JWT passed')
  await f.close()
})
