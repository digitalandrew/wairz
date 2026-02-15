import { create } from 'zustand'
import { listDirectory, readFile, getFileInfo } from '@/api/files'
import { listDocuments, readDocumentContent, createNote as apiCreateNote, updateDocumentContent } from '@/api/documents'
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
  /** Set after navigateToPath completes so FileTree can expand and scroll */
  pendingNavPath: string | null
  documents: ProjectDocument[]
  documentsLoading: boolean
  selectedDocumentId: string | null
  documentDirty: boolean
  documentContent: string | null
}

interface ExplorerActions {
  loadRootDirectory: (projectId: string) => Promise<void>
  loadDirectory: (projectId: string, path: string) => Promise<void>
  selectFile: (projectId: string, node: TreeNode) => Promise<void>
  navigateToPath: (projectId: string, targetPath: string) => Promise<void>
  clearPendingNavPath: () => void
  loadDocuments: (projectId: string) => Promise<void>
  selectDocument: (projectId: string, document: ProjectDocument) => Promise<void>
  setDocumentContent: (content: string) => void
  saveDocument: (projectId: string) => Promise<void>
  createNote: (projectId: string, title: string) => Promise<void>
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
  pendingNavPath: null,
  documents: [],
  documentsLoading: false,
  selectedDocumentId: null,
  documentDirty: false,
  documentContent: null,
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
        documentDirty: false,
        documentContent: null,
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

    navigateToPath: async (projectId, targetPath) => {
      // Expand all parent directories and select the target file.
      // e.g. "/usr/bin/httpd" -> load "/", expand "/usr", expand "/usr/bin", select "httpd"
      const segments = targetPath.split('/').filter(Boolean)
      if (segments.length === 0) return

      // Ensure root is loaded
      if (get().treeData.length === 0) {
        await get().loadRootDirectory(projectId)
      }

      // Expand each parent directory sequentially
      let currentPath = ''
      for (let i = 0; i < segments.length - 1; i++) {
        currentPath += '/' + segments[i]
        // Check if this directory needs loading (has placeholder children)
        const findNode = (nodes: TreeNode[]): TreeNode | null => {
          for (const n of nodes) {
            if (n.id === currentPath) return n
            if (n.children) {
              const found = findNode(n.children)
              if (found) return found
            }
          }
          return null
        }
        const dirNode = findNode(get().treeData)
        if (dirNode?.children?.length === 1 && isPlaceholder(dirNode.children[0])) {
          await get().loadDirectory(projectId, currentPath)
        }
      }

      // Now find and select the target node
      const findTarget = (nodes: TreeNode[]): TreeNode | null => {
        for (const n of nodes) {
          if (n.id === targetPath) return n
          if (n.children) {
            const found = findTarget(n.children)
            if (found) return found
          }
        }
        return null
      }
      const targetNode = findTarget(get().treeData)
      if (targetNode && targetNode.fileType !== 'directory') {
        await get().selectFile(projectId, targetNode)
      }

      // Signal the FileTree to visually expand parents and scroll to this node
      set({ pendingNavPath: targetPath })
    },

    clearPendingNavPath: () => set({ pendingNavPath: null }),

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
        documentDirty: false,
        documentContent: null,
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

    setDocumentContent: (content) => {
      set({ documentContent: content, documentDirty: true })
    },

    saveDocument: async (projectId) => {
      const { selectedDocumentId, documentContent } = get()
      if (!selectedDocumentId || documentContent === null) return
      try {
        const updated = await updateDocumentContent(projectId, selectedDocumentId, documentContent)
        set({
          documentDirty: false,
          fileContent: {
            content: documentContent,
            is_binary: false,
            size: updated.file_size,
            truncated: false,
          },
          // Update the document in the documents list with new metadata
          documents: get().documents.map((d) =>
            d.id === selectedDocumentId ? { ...d, file_size: updated.file_size, sha256: updated.sha256 } : d,
          ),
        })
      } catch {
        // Leave dirty state so user can retry
      }
    },

    createNote: async (projectId, title) => {
      try {
        const doc = await apiCreateNote(projectId, title)
        // Reload documents list then select the new note
        const docs = await listDocuments(projectId)
        set({ documents: docs })
        // Select the new document
        get().selectDocument(projectId, doc)
      } catch {
        // Silently fail — could add error state later
      }
    },

    reset: () => set(initialState),
  }),
)
