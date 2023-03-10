import type { Entry, EntryObject } from './Entry'
import type { Store } from './Store'
import type { EntryListHandle, ScanHandle } from '../crypto'

import { ariesAskar } from '../ariesAskar'
import { AriesAskarError } from '../error'

import { EntryList } from './EntryList'

export class Scan {
  private _handle?: ScanHandle
  private _listHandle?: EntryListHandle
  private store: Store
  private profile?: string
  private category: string
  private tagFilter?: Record<string, unknown>
  private offset?: number
  private limit?: number

  public constructor({
    category,
    limit,
    offset,
    profile,
    tagFilter,
    store,
  }: {
    profile?: string
    category: string
    tagFilter?: Record<string, unknown>
    offset?: number
    limit?: number
    store: Store
  }) {
    this.category = category
    this.profile = profile
    this.tagFilter = tagFilter
    this.offset = offset
    this.limit = limit
    this.store = store
  }

  public get handle() {
    return this._handle
  }

  private async forEach(cb: (row: Entry, index?: number) => void) {
    if (!this.handle) {
      if (!this.store?.handle) throw AriesAskarError.customError({ message: 'Cannot scan from closed store' })
      this._handle = await ariesAskar.scanStart({
        storeHandle: this.store.handle,
        limit: this.limit,
        offset: this.offset,
        tagFilter: this.tagFilter,
        profile: this.profile,
        category: this.category,
      })
    }

    try {
      // Allow max of 256 per fetch operation
      const chunk = this.limit ? Math.min(256, this.limit) : 256
      let recordCount = 0
      // Loop while limit not reached (or no limit specified)
      while (!this.limit || recordCount < this.limit) {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const listHandle = await ariesAskar.scanNext({ scanHandle: this._handle! })
        if (!listHandle) break

        this._listHandle = listHandle
        const list = new EntryList({ handle: this._listHandle })

        recordCount = recordCount + list.length
        for (let index = 0; index < list.length; index++) {
          const entry = list.getEntryByIndex(index)
          cb(entry)
        }

        // If the number of records returned is less than chunk
        // It means we reached the end of the iterator (no more records)
        if (list.length < chunk) {
          break
        }
      }
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      ariesAskar.scanFree({ scanHandle: this._handle! })
    }
  }

  public async fetchAll() {
    const rows: Array<EntryObject> = []
    await this.forEach((row) => rows.push(row.toJson()))
    return rows
  }
}
