### libeds

libeds is a library to authenticate and interact with the EDS service. EDS is an encrypted database service allowing storing data both in a key-value format and row format in the service completely encrypted client-side.

libeds requires a Web3 wallet like Brave Wallet or MetaMask.

It handles key management, generation and synchronization based on the provided wallet. For more details on how this is handled, see below.

It accepts types serializable by MessagePack, as everything is serialized using `msgpackr`.

### Installation

```shell
npm install https://git.maharshi.ninja/root/libeds/archive/0.1.2.tar.gz
yarn add https://git.maharshi.ninja/root/libeds/archive/0.1.2.tar.gz
```

### Usage

```javascript
import { EDS } from 'libeds'
import { BrowserProvider } from 'ethers'

// **IMPORTANT**, do not create an EDS instance using the constructor, use either (new EDS()).initialize or EDS.create
const eds = await EDS.create(new BrowserProvider(window.ethereum, 'any'), {
  // To generate a unique private key for your application, and therefore maintain a different dataset, specify a unique string here.
  appID: '',
  // There's a public instance at wss://eds.gra.১.net:18001
  url: 'wss://eds.gra.১.net:18001'
})

// Key-Value API
await eds.setKey('key', 'value') // The value can be of any type, it's serialized using messagepack.
const v = await eds.getKey('key') 
// v is undefined if key was not found

// Row-level API

// Similar result to getKey
await eds.getRowByKey('primary key')

await eds.upsertRow('primary key', {
  row: 'data'
})

await eds.delRowByKey('primary key')

// An array of rows updated since provided Date
const changes = await eds.getRowsUpdatedSince(new Date(0))
```

If you wish to use a self-generated private key, you can use the WalletWrapper, a simple class implements all that libeds needs, a full provider is not necessary.

```javascript
import { WalletWrapper } from 'libeds/walletwrapper'
import { EDS } from 'libeds'

const eds = await EDS.create(new WalletWrapper({
  privateKey: Buffer.from('...', 'hex')
}), {
  ...
})
```

For a simpler use involving local IndexedDB databases, Dexie support is included.

```javascript
import { EDS } from 'libeds'
import { initializeDexieTables } from 'libeds/dexiesync'

const db = new Dexie('MyDatabase');
// Declare tables, IDs and indexes
db.version(1).stores({
  friends: 'id, name, age'
});
// Syncs the data on the server to the local DB and sets up hooks to sync new changes to the server
await initializeDexieTables({ EDS, tableList: [db.friends] })
```

_WARNING_: Ensure that you DO NOT use a Dexie-generated primary key, because the primary key will desynchronize across devices and will conflict. Use an UUID generated where you insert new documents into the table.

**DO NOTE THAT CONSISTENCY IS NOT GUARANTEED IF CONNECTIVITY IS INTERRUPTED.**

### Key Management

Users are identified by the two-value tuple (Wallet Address, Hash of Wallet Public Key + the App ID).

The library first queries the server to see if an encrypted private key exists for the tuple, if there is one, it's decrypted with the help of the wallet.
If there isn't one, one is randomly generated and encrypted with the wallet public key and stored in the server.
The private key is never revealed to the server, ever. However, the security of the private key and therefore all data encrypted with it is predicated on the user's wallet's security.
