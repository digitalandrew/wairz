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

export interface CodeCleanupResponse {
  binary_path: string
  function: string
  raw_code: string
  cleaned_code: string
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

// ── Security Review types ──

export type ReviewStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type AgentStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

export type ReviewCategory =
  | 'filesystem_survey'
  | 'credential_scan'
  | 'config_audit'
  | 'binary_security'
  | 'permissions_check'
  | 'deep_binary_analysis'
  | 'final_review'

export interface ReviewAgent {
  id: string
  review_id: string
  category: ReviewCategory
  status: AgentStatus
  model: string
  conversation_id: string | null
  scratchpad: string | null
  findings_count: number
  tool_calls_count: number
  error_message: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
  updated_at: string
}

export interface SecurityReview {
  id: string
  project_id: string
  status: ReviewStatus
  selected_categories: ReviewCategory[]
  started_at: string | null
  completed_at: string | null
  created_at: string
  updated_at: string
  agents: ReviewAgent[]
}

export interface ReviewCategoryInfo {
  id: ReviewCategory
  label: string
  description: string
  model: string
  modelLabel: string
  defaultSelected: boolean
}

export const REVIEW_CATEGORIES: ReviewCategoryInfo[] = [
  {
    id: 'filesystem_survey',
    label: 'Filesystem Survey',
    description: 'Map directory structure, identify key components and services',
    model: 'claude-haiku-4-5-20251001',
    modelLabel: 'Haiku',
    defaultSelected: true,
  },
  {
    id: 'credential_scan',
    label: 'Credential Scan',
    description: 'Find hardcoded credentials, private keys, and secrets',
    model: 'claude-haiku-4-5-20251001',
    modelLabel: 'Haiku',
    defaultSelected: true,
  },
  {
    id: 'config_audit',
    label: 'Configuration Audit',
    description: 'Review config files and init scripts for security issues',
    model: 'claude-sonnet-4-20250514',
    modelLabel: 'Sonnet',
    defaultSelected: true,
  },
  {
    id: 'binary_security',
    label: 'Binary Security',
    description: 'Check binary protections, known CVEs, and setuid binaries',
    model: 'claude-sonnet-4-20250514',
    modelLabel: 'Sonnet',
    defaultSelected: true,
  },
  {
    id: 'permissions_check',
    label: 'Permissions Check',
    description: 'Audit filesystem permissions for privilege escalation risks',
    model: 'claude-haiku-4-5-20251001',
    modelLabel: 'Haiku',
    defaultSelected: true,
  },
  {
    id: 'deep_binary_analysis',
    label: 'Deep Binary Analysis',
    description: 'Reverse engineer critical binaries with decompilation',
    model: 'claude-opus-4-20250918',
    modelLabel: 'Opus',
    defaultSelected: false,
  },
  {
    id: 'final_review',
    label: 'Final Review',
    description: 'Synthesize results, deduplicate findings, executive summary',
    model: 'claude-sonnet-4-20250514',
    modelLabel: 'Sonnet',
    defaultSelected: true,
  },
]

export type ReviewSSEEvent =
  | { event: 'review_status_change'; data: { review_id: string; status: ReviewStatus } }
  | { event: 'agent_status_change'; data: { review_id: string; agent_id: string; category: string; status: AgentStatus; tool_calls_count?: number; findings_count?: number; error?: string } }
  | { event: 'agent_tool_call'; data: { review_id: string; agent_id: string; category: string; tool: string; tool_calls_count: number } }
  | { event: 'agent_finding'; data: { review_id: string; agent_id: string; category: string; findings_count: number; title: string; severity: string } }
  | { event: 'review_complete'; data: { review_id: string; status: ReviewStatus } }
  | { event: 'heartbeat'; data: Record<string, never> }

// ── Component Map types ──

export type ComponentNodeType = 'binary' | 'library' | 'script' | 'config' | 'init_script'

export type ComponentEdgeType =
  | 'links_library'
  | 'imports_functions'
  | 'sources_script'
  | 'executes'
  | 'starts_service'
  | 'configures'

export interface ComponentNode {
  id: string
  label: string
  type: ComponentNodeType
  path: string
  size: number
  metadata: Record<string, unknown>
}

export interface ComponentEdge {
  source: string
  target: string
  type: ComponentEdgeType
  details: Record<string, unknown>
}

export interface ComponentGraph {
  nodes: ComponentNode[]
  edges: ComponentEdge[]
  node_count: number
  edge_count: number
  truncated: boolean
}
