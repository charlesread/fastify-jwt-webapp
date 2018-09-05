'use strict'

const jsonwebtoken = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')
const request = require('request')

const implementation = {}

let client
let config
let _config

const getKey = function (header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) return callback(err, null)
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey)
  })
}

implementation.init = function (configFactory) {
  config = configFactory
  _config = configFactory.get()
  client = jwksClient({
    jwksUri: _config.urlJWKS
  })
}

implementation.functionGetJWT = function (_authorizationCode) {
  return new Promise(function (resolve, reject) {
    const requestObject = config.generateTokenRequestObject(_authorizationCode)
    request(requestObject, function (err, response, body) {
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

module.exports = implementation