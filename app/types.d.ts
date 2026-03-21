export interface LauncherInfo {
  launcher_version: string
}

export interface Connection {
  address: string
  heapSize: string
  id: string
  javaHome: string
  javaArgs: string
  name: string
  username: string
  password: string
  group: string
  notes: string
  donotcache: boolean
  lastConnected: number | null
  showConsole: boolean
  engineType: string

  // the below properties are transient and are used only in the UI
  nodeId: string
  parentId: string
}

