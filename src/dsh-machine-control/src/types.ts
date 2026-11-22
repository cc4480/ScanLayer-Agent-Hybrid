/** Wire types shared by the Host half and the browser panels. */

/** One row a panel renders: a list of labelled columns. */
export type TableRow = ReadonlyArray<string>

/** A titled table of rows whose first row is the header. */
export interface Table {
  readonly title: string
  readonly columns: ReadonlyArray<string>
  readonly rows: ReadonlyArray<TableRow>
  /** Rows the Host left out because the list was longer than its cap. */
  readonly truncated?: number
}

/** One labelled fact shown above the tables. */
export interface Fact {
  readonly label: string
  readonly value: string
}

/** A panel's rendered content. */
export interface PanelData {
  /** Stable key of the page that produced the data. */
  readonly page: string
  /** When the Host collected the data, ISO 8601. */
  readonly collectedAt: string
  readonly facts: ReadonlyArray<Fact>
  readonly tables: ReadonlyArray<Table>
  /** Non-fatal problems, such as a command that is not available. */
  readonly notes: ReadonlyArray<string>
}

/** Pages the panels can request. */
export const PAGES = ['overview', 'processes', 'services', 'startup', 'network', 'security', 'packages', 'disk'] as const

/** A panel page id. */
export type PageId = (typeof PAGES)[number]
