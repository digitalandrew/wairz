import { create } from 'zustand'
import { listDirectory, readFile, getFileInfo } from '@/api/files'
import type { FileContent, FileInfo } from '@/types'

export interface TreeNode {
  id: string
  name: string
  fileType: 'file' | 'directory' | 'symlink' | 'other'
  size: number
  permissions: string
  symlinkTarget: string | null
  children?: TreeNode[]
}

const PLACEHOLDER_ID = '__placeholder__'

function makePlaceholder(parentId: string): TreeNode {
  return {
    id: `${parentId}/${PLACEHOLDER_ID}`,
    name: 'Loading…',
    fileType: 'other',
    size: 0,
    permissions: '',
    symlinkTarget: null,
  }
}

export function isPlaceholder(node: TreeNode): boolean {
  return node.id.endsWith(`/${PLACEHOLDER_ID}`)
}

function updateNodeInTree(
  nodes: TreeNode[],
  targetId: string,
  updater: (node: TreeNode) => TreeNode,
): TreeNode[] {
  return nodes.map((node) => {
    if (node.id === targetId) return updater(node)
    if (node.children) {
      const updated = updateNodeInTree(node.children, targetId, updater)
      if (updated !== node.children) return { ...node, children: updated }
    }
    return node
  })
}

interface ExplorerState {
  treeData: TreeNode[]
  selectedPath: string | null
  selectedNode: TreeNode | null
  fileContent: FileContent | null
  fileInfo: FileInfo | null
  contentLoading: boolean
  infoLoading: boolean
  treeError: string | null
}

interface ExplorerActions {
  loadRootDirectory: (projectId: string) => Promise<void>
  loadDirectory: (projectId: string, path: string) => Promise<void>
  selectFile: (projectId: string, node: TreeNode) => Promise<void>
  reset: () => void
}

const initialState: ExplorerState = {
  treeData: [],
  selectedPath: null,
  selectedNode: null,
  fileContent: null,
  fileInfo: null,
  contentLoading: false,
  infoLoading: false,
  treeError: null,
}

export const useExplorerStore = create<ExplorerState & ExplorerActions>(
  (set, get) => ({
    ...initialState,

    loadRootDirectory: async (projectId) => {
      set({ treeError: null })
      try {
        const listing = await listDirectory(projectId, '')
        const nodes = listing.entries.map((entry) => {
          const id = `/${entry.name}`
          const node: TreeNode = {
            id,
            name: entry.name,
            fileType: entry.type,
            size: entry.size,
            permissions: entry.permissions,
            symlinkTarget: entry.symlink_target,
          }
          if (entry.type === 'directory') {
            node.children = [makePlaceholder(id)]
          }
          return node
        })
        // Sort: directories first, then alphabetical
        nodes.sort((a, b) => {
          if (a.fileType === 'directory' && b.fileType !== 'directory') return -1
          if (a.fileType !== 'directory' && b.fileType === 'directory') return 1
          return a.name.localeCompare(b.name)
        })
        set({ treeData: nodes })
      } catch (e) {
        set({
          treeError:
            e instanceof Error ? e.message : 'Failed to load directory',
        })
      }
    },

    loadDirectory: async (projectId, path) => {
      try {
        const listing = await listDirectory(projectId, path)
        const children = listing.entries.map((entry) => {
          const id = `${path}/${entry.name}`
          const node: TreeNode = {
            id,
            name: entry.name,
            fileType: entry.type,
            size: entry.size,
            permissions: entry.permissions,
            symlinkTarget: entry.symlink_target,
          }
          if (entry.type === 'directory') {
            node.children = [makePlaceholder(id)]
          }
          return node
        })
        children.sort((a, b) => {
          if (a.fileType === 'directory' && b.fileType !== 'directory') return -1
          if (a.fileType !== 'directory' && b.fileType === 'directory') return 1
          return a.name.localeCompare(b.name)
        })
        set((state) => ({
          treeData: updateNodeInTree(state.treeData, path, (node) => ({
            ...node,
            children,
          })),
        }))
      } catch {
        // On error, remove placeholder so user can retry by collapsing/expanding
        set((state) => ({
          treeData: updateNodeInTree(state.treeData, path, (node) => ({
            ...node,
            children: [],
          })),
        }))
      }
    },

    selectFile: async (projectId, node) => {
      set({
        selectedPath: node.id,
        selectedNode: node,
        fileContent: null,
        fileInfo: null,
        contentLoading: true,
        infoLoading: true,
      })
      // Fetch content and info concurrently
      const contentPromise = readFile(projectId, node.id)
        .then((content) => {
          // Only update if still the selected file
          if (get().selectedPath === node.id) {
            set({ fileContent: content, contentLoading: false })
          }
        })
        .catch(() => {
          if (get().selectedPath === node.id) {
            set({ contentLoading: false })
          }
        })

      const infoPromise = getFileInfo(projectId, node.id)
        .then((info) => {
          if (get().selectedPath === node.id) {
            set({ fileInfo: info, infoLoading: false })
          }
        })
        .catch(() => {
          if (get().selectedPath === node.id) {
            set({ infoLoading: false })
          }
        })

      await Promise.all([contentPromise, infoPromise])
    },

    reset: () => set(initialState),
  }),
)
