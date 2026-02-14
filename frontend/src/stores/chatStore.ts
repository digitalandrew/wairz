import { create } from 'zustand'
import type { ChatAttachment, ChatDisplayMessage, ConnectionStatus } from '@/types'

let nextId = 0
function uid(): string {
  return `msg-${++nextId}`
}

interface ChatState {
  conversationId: string | null
  messages: ChatDisplayMessage[]
  connectionStatus: ConnectionStatus
  isStreaming: boolean
  error: string | null
  /** Pending file attachments for the next message */
  attachments: ChatAttachment[]
  /** Accumulates streaming assistant text deltas before finalization */
  currentTextAccumulator: string
  /** The id of the in-progress assistant_text message (null when not streaming text) */
  currentAssistantTextId: string | null
}

interface ChatActions {
  setConversationId: (id: string | null) => void
  setConnectionStatus: (status: ConnectionStatus) => void
  addAttachment: (att: ChatAttachment) => void
  removeAttachment: (path: string) => void
  clearAttachments: () => void
  addUserMessage: (content: string, attachments?: ChatAttachment[]) => void
  startAssistantText: () => void
  appendAssistantText: (text: string) => void
  finalizeAssistantText: () => void
  addToolCall: (tool: string, toolUseId: string, input: Record<string, unknown>) => void
  addToolResult: (tool: string, toolUseId: string, output: string, isError?: boolean) => void
  addError: (content: string) => void
  startStreaming: () => void
  stopStreaming: () => void
  reset: () => void
}

const initialState: ChatState = {
  conversationId: null,
  messages: [],
  connectionStatus: 'disconnected',
  isStreaming: false,
  error: null,
  attachments: [],
  currentTextAccumulator: '',
  currentAssistantTextId: null,
}

export const useChatStore = create<ChatState & ChatActions>((set, get) => ({
  ...initialState,

  setConversationId: (id) => set({ conversationId: id }),
  setConnectionStatus: (status) => set({ connectionStatus: status }),

  addAttachment: (att) =>
    set((s) => {
      if (s.attachments.length >= 5) return s
      if (s.attachments.some((a) => a.path === att.path)) return s
      return { attachments: [...s.attachments, att] }
    }),

  removeAttachment: (path) =>
    set((s) => ({ attachments: s.attachments.filter((a) => a.path !== path) })),

  clearAttachments: () => set({ attachments: [] }),

  addUserMessage: (content, attachments) =>
    set((s) => ({
      messages: [
        ...s.messages,
        {
          id: uid(),
          kind: 'user' as const,
          content,
          ...(attachments?.length ? { attachments } : {}),
        },
      ],
    })),

  startAssistantText: () => {
    const id = uid()
    set({ currentAssistantTextId: id, currentTextAccumulator: '' })
  },

  appendAssistantText: (text) => {
    const state = get()
    if (!state.currentAssistantTextId) {
      // Auto-start if not started yet
      const id = uid()
      set({ currentAssistantTextId: id, currentTextAccumulator: text })
      return
    }
    set({ currentTextAccumulator: state.currentTextAccumulator + text })
  },

  finalizeAssistantText: () => {
    const { currentAssistantTextId, currentTextAccumulator } = get()
    if (!currentAssistantTextId || !currentTextAccumulator) {
      set({ currentAssistantTextId: null, currentTextAccumulator: '' })
      return
    }
    set((s) => ({
      messages: [
        ...s.messages,
        { id: currentAssistantTextId, kind: 'assistant_text', content: currentTextAccumulator },
      ],
      currentAssistantTextId: null,
      currentTextAccumulator: '',
    }))
  },

  addToolCall: (tool, toolUseId, input) =>
    set((s) => ({
      messages: [...s.messages, { id: uid(), kind: 'tool_call', tool, toolUseId, input }],
    })),

  addToolResult: (tool, toolUseId, output, isError) =>
    set((s) => ({
      messages: [...s.messages, { id: uid(), kind: 'tool_result', tool, toolUseId, output, isError }],
    })),

  addError: (content) =>
    set((s) => ({
      messages: [...s.messages, { id: uid(), kind: 'error', content }],
      error: content,
    })),

  startStreaming: () => set({ isStreaming: true, error: null }),
  stopStreaming: () => set({ isStreaming: false }),

  reset: () => set(initialState),
}))
