const crypto = require('crypto')
const request = require('superagent')


module.exports = (SECRET_KEY) => {
  function reqValidSignature (req) {
    //API calls using secret keys
    if (req.headers.authorization) {
      const auth = req.headers.authorization

      const theirHash = auth.replace('Signature ', '')

      const ourHash = crypto.createHash('sha1')
        .update(req.rawBody + SECRET_KEY)
        .digest('hex')

      if(theirHash != ourHash) {
        return false
      }
      else {
        return true
      }
    }

    return false
  }

  function rawBody (req, res, next) {
    if (req.get('Content-Type') == 'text/plain') {
      req.rawBody = req.body
    }
    else if (req.body) {
      try {
        req.rawBody = JSON.stringify(req.body)
      }
      catch (ex) {
        req.rawBody = req.body
      }
    }

    next(null)
  }

  function setResponders (req, res, next) {
    res.sendError = (err, status) => {
      status = status || 500
      res.status(status).send(err)
    }

    res.sendJson = (obj) => {
      res.setHeader('Content-Type', 'application/json');
      res.send(JSON.stringify(obj, null, 2))
    }
    res.sendJSON = res.sendJson

    res.resolve = (err, result) => {
      if (err) {
        res.sendError(err)
      }
      else {
        res.send(result)
      }
    }

    next()
  }

  function validSignature (req, res, next) {
    console.log(`valid signa`)
    if (reqValidSignature(req, SECRET_KEY)) {
      next()
    }
    else {
      res.status(403).send('Access denied')
    }
  }

  function signedRequest (method, url, body, secretKey) {
    const hash = crypto.createHash('sha1')
      .update(JSON.stringify(body) + secretKey)
      .digest('hex')

    return request[method](url)
      .send(JSON.stringify(body))
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Signature ' + hash)
  }

  return {
    middleware: {
      rawBody,
      validSignature,
      setResponders
    },
    reqValidSignature,
    signedRequest
  }
}