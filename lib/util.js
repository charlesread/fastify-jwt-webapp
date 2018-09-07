'use strict'

const jsonwebtoken = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')
const request = require('request')

function factory (config) {

  let _config = config.get()
  const implementation = {}
  const client = jwksClient({
    jwksUri: _config.urlJWKS
  })

  const getKey = function (header, callback) {
    client.getSigningKey(header.kid, function (err, key) {
      if (err) return callback(err, null)
      const signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey)
    })
  }

  implementation.functionGetJWT = function (_authorizationCode) {
    return new Promise(function (resolve, reject) {
      request(config.generateTokenRequestObject(_authorizationCode), function (err, response, body) {
        if (err) return reject(err)
        return resolve(body)
      })
    })
  }

  implementation.verifyJWT = function (_token) {
    return new Promise(function (resolve, reject) {
      jsonwebtoken.verify(_token, getKey, function (err, decodedToken) {
        if (err) return reject(err)
        return resolve(decodedToken)
      })
    })
  }

  return implementation
}

module.exports = factory