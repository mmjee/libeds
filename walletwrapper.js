import { Wallet, SigningKey } from 'ethers'
import * as sigUtil from '@metamask/eth-sig-util'

export class WalletWrapper {
  wallet = null
  privateKey = null

  constructor ({ privateKey }) {
    if (!Buffer.isBuffer(privateKey)) {
      throw new Error('Invalid private key')
    }
    this.privateKey = privateKey
    this.wallet = new Wallet(new SigningKey(privateKey))
  }

  async getSigner () {
    return this.wallet
  }

  async send (method, params) {
    switch (method) {
      case 'eth_requestAccounts':
        return [this.wallet.address]
      case 'eth_getEncryptionPublicKey': {
        return sigUtil.getEncryptionPublicKey(this.privateKey.toString('hex'))
      }
      case 'eth_decrypt': {
        const data = Buffer.from(params[0].slice(2), 'hex').toString()
        const buf = sigUtil.decrypt({
          encryptedData: JSON.parse(data),
          privateKey: this.privateKey.toString('hex')
        })
        return buf
      }
      default:
        throw new Error('unimplemented method')
    }
  }
}
