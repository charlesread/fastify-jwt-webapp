'use strict'

require('pino-pretty')

const fastify = require('fastify')({
  https: true,
  // ,
  logger: {
    prettyPrint: true,
    level: 'trace'
  }
})

const fjwt = require('../../plugin')

const config = require('./config')

!async function () {
  // just local TLS
  await fastify.register(require('fastify-tls-keygen'))
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