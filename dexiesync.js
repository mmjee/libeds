import groupBy from 'lodash-es/groupBy'
import cloneDeep from 'lodash-es/cloneDeep'
import _set from 'lodash-es/set'
import { pack as msgpack, unpack as msgunpack } from 'msgpackr'

export async function initializeDexieTables ({ EDS, tableList, syncFilters }) {
  let lastSync = window.localStorage.getItem('eds_last_sync')
  lastSync = lastSync != null ? msgunpack(Buffer.from(lastSync, 'base64')) : new Date(0)
  const _updates = await EDS.getRowsUpdatedSince(lastSync)
  const byTable = groupBy(_updates, '_table')

  for (const table of tableList) {
    const updates = byTable[table.name] ?? []
    const filter = syncFilters[table.name]

    const updatedIDs = await table.bulkPut(updates.map(filter))
    console.log('Synced', table.name, ':', updatedIDs)

    table.hook('deleting', (primKey) => {
      EDS.delRowByKey(primKey).catch(e => console.error(e))
    })
    table.hook('updating', (modifications, primKey, obj) => {
      const cloned = cloneDeep(obj)
      cloned._table = table.name
      for (const [k, v] of Object.entries(modifications)) {
        _set(cloned, k, v)
      }
      EDS.upsertRow(primKey, cloned).catch(e => console.error(e))
    })
    table.hook('creating', (primKey, obj) => {
      obj._table = table.name
      EDS.upsertRow(primKey, obj).catch(e => console.error(e))
    })
  }

  window.localStorage.setItem('eds_last_sync', msgpack(new Date()).toString('base64'))
}
