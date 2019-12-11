import * as ngrok from 'ngrok'
import express from 'express'
import * as Daf from 'daf-core'
import * as SD from 'daf-selective-disclosure'
import * as W3C from 'daf-w3c'
import session from 'express-session'
import socketio from 'socket.io'
import http from 'http'
import exphbs from 'express-handlebars'

import sharedsession from 'express-socket.io-session'

const bodyParser = require('body-parser')
import { core, dataStore } from './setup'
import { webDidDocFromEthrDid } from './web-did-doc'

import Debug from 'debug'
const debug = Debug('main')

let hostname: string

async function main() {
  // Get of create new issuer
  let issuer: Daf.Issuer
  const issuers = await core.identityManager.listIssuers()
  if (issuers.length > 0) {
    issuer = issuers[0]
  } else {
    const types = await core.identityManager.listTypes()
    const did = await core.identityManager.create(types[0])
    issuer = await core.identityManager.issuer(did)
  }

  // Get of create new encryption keyPair
  let keyPair: Daf.KeyPair
  if (core.encryptionKeyManager) {
    const existingKeyPair = await core.encryptionKeyManager.getKeyPairForDid(issuer.did)

    if (!existingKeyPair) {
      keyPair = await core.encryptionKeyManager.createKeyPairForDid(issuer.did)
    } else {
      keyPair = existingKeyPair
    }
    debug('Public Encryption key %o', keyPair.publicKeyHex)
  }

  const app = express()
  app.use(bodyParser.text())
  const sess = session({
    secret: 'keyboard cat',
    cookie: { maxAge: 60000 },
    saveUninitialized: true,
    resave: true,
  })
  app.use(sess)

  app.engine('handlebars', exphbs())
  app.set('view engine', 'handlebars')

  app.get('/', async function(req, res) {
    if (!req.session) {
      return
    }
    let viewcount = 1
    if (req.session.viewcount) {
      req.session.viewcount++
    } else {
      req.session.viewcount = 1
    }
    viewcount = req.session.viewcount

    console.log('APP SID', req.session.id)

    const did = req.session.did
    console.log({ did })
    let jwt
    if (!did) {
      const signAction: SD.ActionSignSdr = {
        type: SD.ActionTypes.signSdr,
        did: issuer.did,
        data: {
          tag: req.sessionID,
          claims: [
            {
              reason: 'We need this information',
              essential: true,
              claimType: 'name',
            },
          ],
        },
      }

      jwt = await core.handleAction(signAction)
    }

    const template = did ? 'home' : 'login'

    res.render(template, { viewcount, did, jwt })
  })

  app.get('/messages', async (req, res) => {
    if (req.session) {
      if (req.session.views) {
        req.session.views++
      } else {
        req.session.views = 1
      }
    }
    const messages = await dataStore.findMessages({})
    res.send(
      'Views' +
        req.session?.views +
        '<br/>Messages:<br/>' +
        messages.map((message: any) => `${message.type} - ${message.hash}<br/>`),
    )
  })

  app.get('/.well-known/did.json', (req, res) =>
    res.send(webDidDocFromEthrDid(issuer.ethereumAddress ? issuer.ethereumAddress : '', hostname, keyPair)),
  )

  app.get('/logout', (req, res) =>
    req.session?.destroy(function(err) {
      res.redirect('/')
    }),
  )

  app.post('/didcomm', async (req, res) => {
    core.onRawMessage({
      raw: req.body,
      meta: [
        {
          sourceType: 'httpsPost',
          sourceId: hostname + '/didcomm',
        },
      ],
    })
    res.send('OK')
  })

  await dataStore.initialize()
  const server = http.createServer(app)
  const io = socketio(server)

  io.use(
    sharedsession(sess, {
      autoSave: true,
    }),
  )

  io.on('connection', function(socket) {
    if (socket.handshake?.session) {
      socket.join(socket.handshake.session.id)
    }
    socket.on('disconnect', function() {
      console.log('user disconnected')
    })
  })

  core.on(Daf.EventTypes.validatedMessage, async (message: Daf.Types.ValidatedMessage) => {
    debug('New message %s', message.hash)
    debug('Meta %O', message.meta)
    console.log(message)
    await dataStore.saveMessage(message)
    if (message.type === W3C.MessageTypes.vp && message.tag) {
      // TODO check for required vcs
      console.log('AAAAAAA')
      await io.in(message.tag).emit('loggedin', { did: message.issuer })
    }
  })

  const port = 8099
  server.listen(port, async () => {
    debug(`Listening on port ${port}!`)
    const url = await ngrok.connect({
      addr: port,
      subdomain: 'someservice',
      region: 'eu',
    })
    debug(`URL: ${url}`)
    debug(`DID Doc: ${url}/.well-known/did.json`)
    debug(`GraphQL: ${url}/graphql`)
    hostname = url.slice(8)
    debug(`did:web:${hostname}`)

    await core.startServices()
    setInterval(async () => {
      await core.syncServices(await dataStore.latestMessageTimestamps())
    }, 5000)
  })
}

main().catch(debug)