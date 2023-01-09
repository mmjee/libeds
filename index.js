import { decode as msgunpack, encode as msgpack } from 'msgpackr'
import { providers as EthersProviders, utils as EthersUtils } from 'ethers'
import blake2b from 'blake2b'
import tweetnacl from 'tweetnacl'
import { encrypt as encryptForWallet } from '@metamask/eth-sig-util'
import base85 from 'base85'
import { Mutex } from 'async-mutex'
import sleep from 'sleep-promise'

import { randomBytes } from 'crypto'

const STATE_AWAITING_CHALLENGE = 0
const STATE_AWAITING_RESPONSE = 1
const STATE_AWAITING_WELCOME = 2
const STATE_FULLY_AUTHENTICATED = 3
const MESSAGE_PREFIX = 'This is a randomly generated string used to challenge your wallet to prove its ownership of EDS resources, do not worry: '

const REQ_KEY_GET = 0x11
const REQ_KEY_SET = 0x1A
const REQ_KEY_DEL = 0x1B
const REQ_ROW_GET = 0x21
const REQ_ROW_UPDATES = 0x22
const REQ_ROW_UPSERT = 0x2A
const REQ_ROW_DELETE = 0x2B

const EDS_VER_TO_ETH_VER = {
  0x81: 'x25519-xsalsa20-poly1305'
}

function easyHash (buf) {
  const h = blake2b(64)
  h.update(Buffer.isBuffer(buf) ? buf : Buffer.from(buf))
  return Buffer.from(h.digest())
}

function randUint32 () {
  const randBytes = randomBytes(32 / 8)
  return randBytes.readUint32LE(0)
}

export class EncryptedDatabase {
  state = STATE_AWAITING_CHALLENGE
  IDToResolver = new Map()
  onInitialized = () => null

  // Initialization
  async initialize (provider, { appID = null, url }) {
    this.wsURL = url
    this.provider = new EthersProviders.Web3Provider(provider)
    this.lock = new Mutex()
    this.writeLock = new Mutex()
    this.writeLockRelease = await this.writeLock.acquire()

    await this.provider.send('eth_requestAccounts', [])
    this.signer = this.provider.getSigner()
    this.address = await this.signer.getAddress()
    this.addressBytes = EthersUtils.arrayify(this.address)

    this._walletPubKey = await this.provider.send('eth_getEncryptionPublicKey', [this.address])
    const pkBytes = Buffer.from(this._walletPubKey, 'base64')
    this._walletPKHash = easyHash(appID == null ? pkBytes : Buffer.concat([pkBytes, Buffer.from('_' + appID)]) )

    this.initializeSocket()
    return new Promise(resolve => {
      this.onInitialized = resolve
    })
  }

  // Private functions ⬇️
  initializeSocket () {
    this.ws = new WebSocket(this.wsURL)
    this.ws.binaryType = 'arraybuffer'
    this.ws.addEventListener('error', this.onClosedOrError)
    this.ws.addEventListener('close', this.onClosedOrError)
    this.ws.addEventListener('message', this.onMessage)
  }

  sendMessage (msg) {
    this.ws.send(msgpack(msg))
  }

  async sendTypedMessage (type = null, msg) {
    await this.writeLock.waitForUnlock()
    this.ws.send(Buffer.concat([new Uint8Array([type]), msgpack(msg)]))
  }

  waitForReply (id) {
    return new Promise(resolve => {
      this.IDToResolver.set(id, resolve)
    })
  }

  onClosedOrError = async () => {
    this.writeLockRelease = await this.writeLock.acquire()
    this.state = STATE_AWAITING_CHALLENGE
    this.onInitialized = () => null
    await sleep(1000)
    this.initializeSocket()
  }

  onMessage = async (msg) => {
    const release = await this.lock.acquire()
    try {
      await this.handleMessage(msg)
    } finally {
      release()
    }
  }

  handleMessage = async (msg) => {
    const data = msgunpack(Buffer.from(msg.data))

    switch (this.state) {
      case STATE_AWAITING_CHALLENGE: {
        const sig = EthersUtils.arrayify(await this.signer.signMessage(MESSAGE_PREFIX + data.ChallengeBuffer))
        this.sendMessage({
          Address: this.addressBytes,
          Signature: sig,
          PKHash: this._walletPKHash
        })
        this.state = STATE_AWAITING_RESPONSE
        break
      }
      case STATE_AWAITING_RESPONSE: {
        if (data.KeyFound) {
          const keyCompressed = msgunpack(data.EncryptedPrivateKey)
          const keyUncompressed = {
            version: EDS_VER_TO_ETH_VER[keyCompressed[0]],
            ciphertext: keyCompressed[1].toString('base64'),
            nonce: keyCompressed[2].toString('base64'),
            ephemPublicKey: keyCompressed[3].toString('base64')
          }
          const privateKey85 = await this.provider.send('eth_decrypt', ['0x' + Buffer.from(JSON.stringify(keyUncompressed)).toString('hex'), this.address])
          this.privateKey = base85.decode(privateKey85, 'z85')
          this.publicKey = tweetnacl.box.keyPair.fromSecretKey(this.privateKey).publicKey
        } else {
          const { publicKey, secretKey } = tweetnacl.box.keyPair()
          this.publicKey = Buffer.from(publicKey)
          this.privateKey = Buffer.from(secretKey)
          const encPrivateKeyECIES = encryptForWallet({
            publicKey: this._walletPubKey,
            data: base85.encode(this.privateKey, 'z85'),
            version: 'x25519-xsalsa20-poly1305'
          })
          const encPrivateKey = msgpack([
            0x81,
            Buffer.from(encPrivateKeyECIES.ciphertext, 'base64'),
            Buffer.from(encPrivateKeyECIES.nonce, 'base64'),
            Buffer.from(encPrivateKeyECIES.ephemPublicKey, 'base64')
          ])
          this.sendMessage(encPrivateKey)
        }
        this.state = STATE_AWAITING_WELCOME
        break
      }
      case STATE_AWAITING_WELCOME: {
        console.log('EDS | Received welcome, logged into the EDS system:', data)
        this.onInitialized()
        this.state = STATE_FULLY_AUTHENTICATED
        try {
          this.writeLockRelease()
          this.writeLockRelease = null
        } catch (e) {
          console.log('Errored while releasing write lock!')
          console.error(e)
        }
        break
      }
      case STATE_FULLY_AUTHENTICATED: {
        if (data.ID) {
          const resolver = this.IDToResolver.get(data.ID)
          if (resolver != null) {
            this.IDToResolver.delete(data.ID)
            resolver(data)
          }
        } else {
          console.warn('Weird or unimplemented message:', data)
        }
        break
      }
      default: {
        console.warn('Ignoring:', data)
      }
    }
  }

  decryptDataResponse = async (id) => {
    const { Exists, Data } = await this.waitForReply(id)
    if (!Exists) {
      return undefined
    }
    const nonce = Data.subarray(0, tweetnacl.secretbox.nonceLength)
    const ciphertext = Data.subarray(tweetnacl.secretbox.nonceLength)
    const data = tweetnacl.secretbox.open(ciphertext, nonce, this.privateKey)
    return msgunpack(data)
  }

  encryptData = (data) => {
    const vBuf = msgpack(data)
    const nonce = randomBytes(tweetnacl.secretbox.nonceLength)
    const ciphertext = tweetnacl.secretbox(vBuf, nonce, this.privateKey)
    return Buffer.concat([nonce, ciphertext])
  }

  // Private functions ⬆️
  // Public functions ⬇️
  getKey = async (key) => {
    const hash = easyHash(key)
    const ID = randUint32()
    await this.sendTypedMessage(REQ_KEY_GET, {
      ID,
      Key: hash
    })
    return this.decryptDataResponse(ID)
  }

  delKey = async (key) => {
    const hash = easyHash(key)
    const ID = randUint32()
    await this.sendTypedMessage(REQ_KEY_DEL, {
      ID,
      Key: hash
    })
    return this.decryptDataResponse(ID)
  }

  setKey = async (key, value) => {
    const ID = randUint32()
    await this.sendTypedMessage(REQ_KEY_SET, {
      ID,
      Key: easyHash(key),
      Value: this.encryptData(value)
    })
    return this.waitForReply(ID)
  }

  getRowByKey = async (key) => {
    const hash = easyHash(msgpack(key))
    const ID = randUint32()
    await this.sendTypedMessage(REQ_ROW_GET, {
      ID,
      KeyHash: hash
    })
    return this.decryptDataResponse(ID)
  }

  delRowByKey = async (key) => {
    const hash = easyHash(msgpack(key))
    const ID = randUint32()
    await this.sendTypedMessage(REQ_ROW_DELETE, {
      ID,
      KeyHash: hash
    })
    return this.decryptDataResponse(ID)
  }

  getRowsUpdatedSince = async (time) => {
    const ID = randUint32()
    await this.sendTypedMessage(REQ_ROW_UPDATES, {
      ID,
      Since: time
    })
    const { Rows } = await this.waitForReply(ID)
    return Rows.map(row => {
      const nonce = row.Data.subarray(0, tweetnacl.secretbox.nonceLength)
      const ciphertext = row.Data.subarray(tweetnacl.secretbox.nonceLength)
      const data = tweetnacl.secretbox.open(ciphertext, nonce, this.privateKey)
      return msgunpack(data)
    })
  }

  upsertRow = async (primaryKey, row) => {
    const KeyHash = easyHash(msgpack(primaryKey))
    const data = this.encryptData(row)
    const ID = randUint32()

    await this.sendTypedMessage(REQ_ROW_UPSERT, {
      ID,
      KeyHash,
      Data: data
    })
    return this.waitForReply(ID)
  }
}
