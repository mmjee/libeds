import groupBy from 'lodash.groupby'
import { pack as msgpack, unpack as msgunpack } from 'msgpackr'

export async function initializeDexieTables ({ EDS, tableList }) {
  let lastSync = window.localStorage.getItem('eds_last_sync')
  lastSync = lastSync != null ? msgunpack(Buffer.from(lastSync, 'base64')) : new Date(0)
  const _updates = await EDS.getRowsUpdatedSince(lastSync)
  const byTable = groupBy(_updates, '_table')

  for (const table of tableList) {
    const updates = byTable[table.name] ?? []
    const updatedIDs = await table.bulkPut(updates)
    console.log('Synced', table.name, ':', updatedIDs)

    table.hook('deleting', (primKey) => {
      EDS.delRowByKey(primKey).catch(e => console.error(e))
    })
    table.hook('updating', (_, primKey, obj) => {
      obj._table = table.name
      EDS.upsertRow(primKey, obj).catch(e => console.error(e))
    })
    table.hook('creating', (primKey, obj) => {
      obj._table = table.name
      EDS.upsertRow(primKey, obj).catch(e => console.error(e))
    })
  }

  window.localStorage.setItem('eds_last_sync', msgpack(new Date()).toString('base64'))
}
