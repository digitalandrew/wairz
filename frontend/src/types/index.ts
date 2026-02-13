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
