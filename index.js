const crypto = require('crypto')
const request = require('superagent')
const debug = require('debug')('vinexpress')

module.exports = (SECRET_KEY) => {
  debug('Loading vinexpress with')
  function reqValidSignature (req) {
    //API calls using secret keys
    if (req.headers.authorization) {
      const auth = req.headers.authorization

      const theirHash = auth.replace('Signature ', '')

      const ourHash = crypto.createHash('sha1')
        .update(req.rawBody + SECRET_KEY)
        .digest('hex')


      if(theirHash != ourHash) {
        debug('Hashes do not match')
        debug('req.rawBody', req.rawBody)
        debug('req.body', req.body)
        debug('Ours:   ' + ourHash)
        debug('Theirs: ' + theirHash)
        return false
      }
      else {
        return true
      }
    }
    else {
      debug('No authorization header present')
    }

    return false
  }

  function textBody (req, res, next){
    if (req.is('text/*')) {
      req.text = ''
      req.setEncoding('utf8')
      req.on('data', function(chunk){ req.text += chunk })
      req.on('end', () => {
        req.body = req.text
        req.rawBody = req.body
        next()
      });
    } else {
      next()
    }
  }

  function rawBody (req, res, next) {
    if (req.get('Content-Type') == 'text/plain') {
      debug('Content-Type is text/plain for rawBody')
      req.rawBody = req.body
    }
    else if (req.body) {
      try {
        debug('JSON Stingifying body to create rawBody')
        req.rawBody = JSON.stringify(req.body)
      }
      catch (ex) {
        debug('JSON stringify failed, setting rawBody = body')
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
    debug('Validating signature')
    if (reqValidSignature(req, SECRET_KEY)) {
      debug('Is valid signature')
      next()
    }
    else {
      debug('Invalid signature')
      res.status(403).send('Access denied')
    }
  }

  function signedRequest (method, url, body, secretKey) {
    debug('Body to submit', body)
    debug('secretKey', secretKey)
    const hash = crypto.createHash('sha1')
      .update(JSON.stringify(body) + secretKey)
      .digest('hex')

    return request[method](url)
      .send(JSON.stringify(body))
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Signature ' + hash)
  }

  function fromPromise (req, res, next) {
    res.fromPromise = promise => {
      return promise
        .then(result => res.status(result.status).send(result.body))
        .catch(err => res.status(err.status).send(err.body))
    }
    next()
  }

  return {
    middleware: {
      rawBody,
      validSignature,
      setResponders,
      textBody,
      fromPromise
    },
    reqValidSignature,
    signedRequest
  }
}
