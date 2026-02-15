export interface Project {
  id: string
  name: string
  description: string | null
  status: string
  created_at: string
  updated_at: string
}

export interface ProjectDetail extends Project {
  firmware: FirmwareSummary[]
}

export interface FirmwareSummary {
  id: string
  original_filename: string | null
  sha256: string
  file_size: number | null
  architecture: string | null
  endianness: string | null
  os_info: string | null
  created_at: string
}

export interface FirmwareDetail extends FirmwareSummary {
  project_id: string
  storage_path: string | null
  extracted_path: string | null
  unpack_log: string | null
}

export interface FileEntry {
  name: string
  type: 'file' | 'directory' | 'symlink' | 'other'
  size: number
  permissions: string
  symlink_target: string | null
}

export interface DirectoryListing {
  path: string
  entries: FileEntry[]
  truncated: boolean
}

export interface FileContent {
  content: string
  is_binary: boolean
  size: number
  truncated: boolean
  encoding?: string
}

export interface FileInfo {
  path: string
  type: string
  mime_type: string
  size: number
  permissions: string
  sha256: string | null
  elf_info: Record<string, unknown> | null
}

export interface SearchResult {
  pattern: string
  matches: string[]
  truncated: boolean
}

// ── Analysis types ──

export interface FunctionInfo {
  name: string
  offset: number
  size: number
}

export interface FunctionListResponse {
  binary_path: string
  functions: FunctionInfo[]
}

export interface DisassemblyResponse {
  binary_path: string
  function: string
  disassembly: string
}

export interface DecompilationResponse {
  binary_path: string
  function: string
  decompiled_code: string
}

export interface BinaryProtections {
  nx: boolean
  relro: string
  canary: boolean
  pie: boolean
  fortify: boolean
  stripped: boolean
  error?: string
}

export interface BinaryInfoResponse {
  binary_path: string
  info: Record<string, unknown>
  protections: BinaryProtections
}

// ── Model types ──

export interface ModelOption {
  id: string
  label: string
  cost: 'Least expensive' | 'Moderate' | 'Most expensive'
  description: string
}

export const MODEL_OPTIONS: ModelOption[] = [
  {
    id: 'claude-haiku-4-5-20251001',
    label: 'Haiku 4.5',
    cost: 'Least expensive',
    description: 'Fast responses, good for quick questions and simple tasks',
  },
  {
    id: 'claude-sonnet-4-20250514',
    label: 'Sonnet 4',
    cost: 'Moderate',
    description: 'Balanced cost and capability, strong tool use and analysis',
  },
  {
    id: 'claude-opus-4-20250918',
    label: 'Opus 4',
    cost: 'Most expensive',
    description: 'Highest capability, best for complex RE and deep analysis',
  },
]

export const DEFAULT_MODEL = 'claude-sonnet-4-20250514'

// ── Finding types ──

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingStatus = 'open' | 'confirmed' | 'false_positive' | 'fixed'

export interface Finding {
  id: string
  project_id: string
  conversation_id: string | null
  title: string
  severity: Severity
  description: string | null
  evidence: string | null
  file_path: string | null
  line_number: number | null
  cve_ids: string[] | null
  cwe_ids: string[] | null
  status: FindingStatus
  created_at: string
  updated_at: string
}

export interface FindingCreate {
  title: string
  severity: Severity
  description?: string
  evidence?: string
  file_path?: string
  line_number?: number
  cve_ids?: string[]
  cwe_ids?: string[]
  conversation_id?: string
}

export interface FindingUpdate {
  title?: string
  severity?: Severity
  description?: string
  evidence?: string
  file_path?: string
  line_number?: number
  cve_ids?: string[]
  cwe_ids?: string[]
  status?: FindingStatus
}

// ── Document types ──

export interface ProjectDocument {
  id: string
  project_id: string
  original_filename: string
  description: string | null
  content_type: string
  file_size: number
  sha256: string
  storage_path: string
  created_at: string
}

export interface DocumentContent {
  content: string
  content_type: string
  filename: string
  size: number
}

// ── Chat types ──

export interface ChatAttachment {
  path: string
  name: string
}

export interface Conversation {
  id: string
  project_id: string
  title: string | null
  created_at: string
  updated_at: string
}

export interface ConversationDetail extends Conversation {
  messages: Record<string, unknown>[]
}

export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected'

export type ChatDisplayMessage =
  | { id: string; kind: 'user'; content: string; attachments?: ChatAttachment[] }
  | { id: string; kind: 'assistant_text'; content: string }
  | { id: string; kind: 'tool_call'; tool: string; toolUseId: string; input: Record<string, unknown> }
  | { id: string; kind: 'tool_result'; tool: string; toolUseId: string; output: string; isError?: boolean }
  | { id: string; kind: 'error'; content: string }

export type WSEvent =
  | { type: 'assistant_text'; content: string; delta: boolean }
  | { type: 'tool_call'; tool: string; tool_use_id: string; input: Record<string, unknown> }
  | { type: 'tool_result'; tool: string; tool_use_id: string; output: string }
  | { type: 'error'; content: string }
  | { type: 'done' }
