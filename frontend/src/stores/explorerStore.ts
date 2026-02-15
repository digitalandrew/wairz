import { create } from 'zustand'
import { listDirectory, readFile, getFileInfo } from '@/api/files'
import { listDocuments, readDocumentContent } from '@/api/documents'
import type { FileContent, FileInfo, ProjectDocument } from '@/types'

/** MIME types that indicate text content (even though some start with application/) */
const TEXT_MIME_PREFIXES = ['text/', 'application/json', 'application/xml', 'application/javascript']

function isBinaryMime(mime: string): boolean {
  return !TEXT_MIME_PREFIXES.some((prefix) => mime.startsWith(prefix))
}

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
  documents: ProjectDocument[]
  documentsLoading: boolean
  selectedDocumentId: string | null
}

interface ExplorerActions {
  loadRootDirectory: (projectId: string) => Promise<void>
  loadDirectory: (projectId: string, path: string) => Promise<void>
  selectFile: (projectId: string, node: TreeNode) => Promise<void>
  loadDocuments: (projectId: string) => Promise<void>
  selectDocument: (projectId: string, document: ProjectDocument) => Promise<void>
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
  documents: [],
  documentsLoading: false,
  selectedDocumentId: null,
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
        selectedDocumentId: null,
      })

      // Fetch file info first to determine if binary
      try {
        const info = await getFileInfo(projectId, node.id)
        if (get().selectedPath !== node.id) return
        set({ fileInfo: info, infoLoading: false })

        // If binary, skip content fetch — HexViewer manages its own data
        if (isBinaryMime(info.mime_type)) {
          set({ contentLoading: false })
          return
        }
      } catch {
        if (get().selectedPath !== node.id) return
        set({ infoLoading: false })
      }

      // Fetch text content
      try {
        const content = await readFile(projectId, node.id)
        if (get().selectedPath === node.id) {
          set({ fileContent: content, contentLoading: false })
        }
      } catch {
        if (get().selectedPath === node.id) {
          set({ contentLoading: false })
        }
      }
    },

    loadDocuments: async (projectId) => {
      set({ documentsLoading: true })
      try {
        const docs = await listDocuments(projectId)
        set({ documents: docs, documentsLoading: false })
      } catch {
        set({ documentsLoading: false })
      }
    },

    selectDocument: async (projectId, document) => {
      set({
        selectedDocumentId: document.id,
        selectedPath: null,
        selectedNode: null,
        fileContent: null,
        fileInfo: null,
        contentLoading: true,
        infoLoading: false,
      })

      try {
        const result = await readDocumentContent(projectId, document.id)
        if (get().selectedDocumentId === document.id) {
          set({
            fileContent: {
              content: result.content,
              is_binary: false,
              size: result.size,
              truncated: false,
            },
            contentLoading: false,
          })
        }
      } catch {
        if (get().selectedDocumentId === document.id) {
          set({ contentLoading: false })
        }
      }
    },

    reset: () => set(initialState),
  }),
)
