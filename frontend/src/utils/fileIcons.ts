import {
  Folder,
  FolderOpen,
  File,
  FileText,
  FileCode,
  FileJson,
  FileKey,
  Shield,
  Terminal,
  Image,
  Cog,
  Link,
  type LucideIcon,
} from 'lucide-react'

const extensionIconMap: Record<string, LucideIcon> = {
  // Scripts
  sh: Terminal,
  bash: Terminal,
  zsh: Terminal,
  fish: Terminal,
  py: FileCode,
  pl: FileCode,
  rb: FileCode,
  lua: FileCode,
  php: FileCode,
  js: FileCode,
  // Config
  conf: Cog,
  cfg: Cog,
  ini: Cog,
  yml: Cog,
  yaml: Cog,
  toml: Cog,
  xml: FileCode,
  // Data
  json: FileJson,
  csv: FileText,
  // Security
  pem: FileKey,
  key: FileKey,
  crt: Shield,
  cert: Shield,
  csr: Shield,
  // Images
  png: Image,
  jpg: Image,
  jpeg: Image,
  gif: Image,
  bmp: Image,
  svg: Image,
  ico: Image,
  // Text
  txt: FileText,
  md: FileText,
  log: FileText,
  // C/C++
  c: FileCode,
  h: FileCode,
  cpp: FileCode,
  hpp: FileCode,
}

export function getFileIcon(
  name: string,
  fileType: string,
  isOpen?: boolean,
): LucideIcon {
  if (fileType === 'directory') return isOpen ? FolderOpen : Folder
  if (fileType === 'symlink') return Link

  const ext = name.split('.').pop()?.toLowerCase() ?? ''
  return extensionIconMap[ext] ?? File
}

const extensionLanguageMap: Record<string, string> = {
  sh: 'shell',
  bash: 'shell',
  zsh: 'shell',
  fish: 'shell',
  py: 'python',
  pl: 'perl',
  rb: 'ruby',
  lua: 'lua',
  php: 'php',
  js: 'javascript',
  ts: 'typescript',
  c: 'c',
  h: 'c',
  cpp: 'cpp',
  hpp: 'cpp',
  java: 'java',
  go: 'go',
  rs: 'rust',
  json: 'json',
  xml: 'xml',
  html: 'html',
  htm: 'html',
  css: 'css',
  yaml: 'yaml',
  yml: 'yaml',
  toml: 'ini',
  ini: 'ini',
  conf: 'ini',
  cfg: 'ini',
  sql: 'sql',
  md: 'markdown',
  asm: 'assembly',
  s: 'assembly',
  mk: 'makefile',
  makefile: 'makefile',
  dockerfile: 'dockerfile',
}

export function getMonacoLanguage(name: string): string {
  const lower = name.toLowerCase()
  // Handle special filenames
  if (lower === 'makefile' || lower === 'gnumakefile') return 'makefile'
  if (lower === 'dockerfile') return 'dockerfile'

  const ext = lower.split('.').pop() ?? ''
  return extensionLanguageMap[ext] ?? 'plaintext'
}
