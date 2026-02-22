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
  kernel_path: string | null
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

export interface ImportInfo {
  name: string
  libname: string | null
}

export interface ImportsResponse {
  binary_path: string
  imports: ImportInfo[]
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

// ── Finding types ──

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingStatus = 'open' | 'confirmed' | 'false_positive' | 'fixed'
export type FindingSource = 'manual' | 'ai_discovered' | 'sbom_scan' | 'fuzzing' | 'security_review'

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
  source: FindingSource
  component_id: string | null
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
  source?: FindingSource
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
  source?: FindingSource
}

// ── SBOM types ──

export type DetectionSource = 'package_manager' | 'binary_strings' | 'library_soname' | 'kernel_modules' | 'config_file'
export type DetectionConfidence = 'high' | 'medium' | 'low'

export interface SbomComponent {
  id: string
  firmware_id: string
  name: string
  version: string | null
  type: string
  cpe: string | null
  purl: string | null
  supplier: string | null
  detection_source: DetectionSource
  detection_confidence: DetectionConfidence
  file_paths: string[] | null
  metadata: Record<string, unknown>
  vulnerability_count: number
  created_at: string
}

export interface SbomVulnerability {
  id: string
  component_id: string
  cve_id: string
  cvss_score: number | null
  cvss_vector: string | null
  severity: Severity
  description: string | null
  published_date: string | null
  finding_id: string | null
  component_name: string | null
  component_version: string | null
}

export interface SbomGenerateResponse {
  components: SbomComponent[]
  total: number
  cached: boolean
}

export interface SbomSummary {
  total_components: number
  components_by_type: Record<string, number>
  components_with_vulns: number
  total_vulnerabilities: number
  vulns_by_severity: Record<string, number>
  scan_date: string | null
}

export interface VulnerabilityScanResult {
  status: string
  total_components_scanned: number
  total_vulnerabilities_found: number
  findings_created: number
  vulns_by_severity: Record<string, number>
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

// ── Emulation types ──

export type EmulationMode = 'user' | 'system'
export type EmulationStatus = 'created' | 'starting' | 'running' | 'stopped' | 'error'

export interface PortForward {
  host: number
  guest: number
}

export interface EmulationSession {
  id: string
  project_id: string
  firmware_id: string
  mode: EmulationMode
  status: EmulationStatus
  architecture: string | null
  binary_path: string | null
  arguments: string | null
  port_forwards: PortForward[]
  error_message: string | null
  started_at: string | null
  stopped_at: string | null
  created_at: string
}

export interface EmulationStartRequest {
  mode: EmulationMode
  binary_path?: string
  arguments?: string
  port_forwards?: PortForward[]
  kernel_name?: string
  init_path?: string
  pre_init_script?: string
}

export interface EmulationPreset {
  id: string
  project_id: string
  name: string
  description: string | null
  mode: EmulationMode
  binary_path: string | null
  arguments: string | null
  architecture: string | null
  port_forwards: PortForward[] | null
  kernel_name: string | null
  init_path: string | null
  pre_init_script: string | null
  created_at: string
  updated_at: string
}

export interface EmulationPresetCreate {
  name: string
  description?: string
  mode: EmulationMode
  binary_path?: string
  arguments?: string
  architecture?: string
  port_forwards?: PortForward[]
  kernel_name?: string
  init_path?: string
  pre_init_script?: string
}

export interface EmulationPresetUpdate {
  name?: string
  description?: string
  mode?: EmulationMode
  binary_path?: string
  arguments?: string
  architecture?: string
  port_forwards?: PortForward[]
  kernel_name?: string
  init_path?: string
  pre_init_script?: string
}

// ── Kernel types ──

export interface KernelInfo {
  name: string
  architecture: string
  description: string
  file_size: number
  uploaded_at: string
}

export interface KernelListResponse {
  kernels: KernelInfo[]
  total: number
}

export interface EmulationExecResponse {
  stdout: string
  stderr: string
  exit_code: number
  timed_out: boolean
}

// ── Fuzzing types ──

export type FuzzingStatus = 'created' | 'running' | 'stopped' | 'completed' | 'error'
export type CrashExploitability = 'exploitable' | 'probably_exploitable' | 'probably_not' | 'unknown'

export interface FuzzingStats {
  execs_per_sec: number
  total_execs: number
  corpus_count: number
  saved_crashes: number
  saved_hangs: number
  stability: string | number
  bitmap_cvg: string | number
  last_find: number
  run_time: number
}

export interface FuzzingCampaign {
  id: string
  project_id: string
  firmware_id: string
  binary_path: string
  status: FuzzingStatus
  config: Record<string, unknown> | null
  stats: FuzzingStats | null
  crashes_count: number
  container_id: string | null
  error_message: string | null
  started_at: string | null
  stopped_at: string | null
  created_at: string
}

export interface FuzzingCrash {
  id: string
  campaign_id: string
  crash_filename: string
  crash_size: number | null
  signal: string | null
  stack_trace: string | null
  exploitability: CrashExploitability | null
  triage_output: string | null
  finding_id: string | null
  created_at: string
}

export interface FuzzingCrashDetail extends FuzzingCrash {
  crash_input_hex: string | null
}

export interface FuzzingTargetAnalysis {
  binary_path: string
  fuzzing_score: number
  input_sources: string[]
  dangerous_functions: string[]
  network_functions: string[]
  protections: Record<string, unknown>
  recommended_strategy: string
  function_count: number
  imports_of_interest: string[]
  file_size: number
  error?: string | null
}

export interface FuzzingCampaignCreateRequest {
  binary_path: string
  timeout_per_exec?: number
  memory_limit?: number
  dictionary?: string
  seed_corpus?: string[]
}

// ── Component Map types ──

export type ComponentNodeType = 'binary' | 'library' | 'script' | 'config' | 'init_script' | 'kernel_module'

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
