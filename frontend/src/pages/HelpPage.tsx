import { useState } from 'react'
import { ChevronRight, HelpCircle } from 'lucide-react'

interface SectionProps {
  title: string
  children: React.ReactNode
  defaultOpen?: boolean
}

function Section({ title, children, defaultOpen = false }: SectionProps) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className="border-b border-border last:border-b-0">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-1 py-3 text-left text-sm font-semibold transition-colors hover:text-primary"
      >
        <ChevronRight
          className={`h-4 w-4 shrink-0 text-muted-foreground transition-transform ${open ? 'rotate-90' : ''}`}
        />
        {title}
      </button>
      {open && (
        <div className="pb-4 pl-6 pr-1 text-sm leading-relaxed text-muted-foreground">
          {children}
        </div>
      )}
    </div>
  )
}

export default function HelpPage() {
  return (
    <div className="mx-auto max-w-3xl py-8">
      <div className="mb-8 flex items-center gap-3">
        <HelpCircle className="h-7 w-7 text-primary" />
        <h1 className="text-2xl font-bold">Help</h1>
      </div>

      <div className="rounded-lg border border-border bg-card">
        <Section title="Getting Started" defaultOpen>
          <p className="mb-3">
            Wairz is an AI-assisted firmware reverse engineering and security
            assessment platform. The typical workflow is:
          </p>
          <ol className="mb-3 list-inside list-decimal space-y-1">
            <li>
              <strong>Create a project</strong> from the Projects dashboard
            </li>
            <li>
              <strong>Upload firmware</strong> (binary image file)
            </li>
            <li>
              <strong>Unpack</strong> the firmware to extract the filesystem
            </li>
            <li>
              <strong>Explore</strong> the extracted files using the File
              Explorer
            </li>
            <li>
              <strong>Analyze</strong> binaries, configs, and scripts with the
              AI assistant
            </li>
            <li>
              <strong>Review findings</strong> and export a security report
            </li>
          </ol>
          <p>
            Use the sidebar to navigate between projects and their sub-pages
            (Overview, File Explorer, Findings, Component Map, SBOM,
            Emulation, Fuzzing).
          </p>
        </Section>

        <Section title="Projects">
          <p className="mb-3">
            Projects are the top-level container for a firmware analysis session.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Create:</strong> Click "New Project" on the Projects page.
              Give it a name and optional description.
            </li>
            <li>
              <strong>Status:</strong> Projects show their current state &mdash;{' '}
              <em>created</em>, <em>unpacking</em>, <em>ready</em>, or{' '}
              <em>error</em>.
            </li>
            <li>
              <strong>Delete:</strong> Use the delete button on the project
              Overview page. This removes the project, firmware data, and
              findings.
            </li>
          </ul>
        </Section>

        <Section title="Firmware Upload & Unpacking">
          <p className="mb-3">
            After creating a project, upload a firmware binary image from the
            project Overview page.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Supported formats:</strong> SquashFS, JFFS2, UBIFS,
              CramFS, ext, CPIO, and other formats supported by binwalk.
            </li>
            <li>
              <strong>Upload:</strong> Drag and drop or click to select a file.
              A progress bar shows the upload status.
            </li>
            <li>
              <strong>Unpack:</strong> Once uploaded, click "Unpack Firmware" to
              extract the filesystem. This detects the architecture (ARM, MIPS,
              x86, etc.) and endianness automatically.
            </li>
            <li>
              <strong>Errors:</strong> If extraction fails, the project status
              changes to "error" and the unpack log is available for
              troubleshooting.
            </li>
          </ul>
        </Section>

        <Section title="Project Documents">
          <p className="mb-3">
            Attach reference documents and notes to your project for context
            during analysis.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Upload documents:</strong> Upload PDFs, datasheets, or
              other reference files from the project Overview.
            </li>
            <li>
              <strong>Create notes:</strong> Write and edit Markdown notes
              directly in the browser.
            </li>
            <li>
              <strong>WAIRZ.md:</strong> A special document created
              automatically for each project. The AI assistant reads it via
              the{' '}
              <code className="rounded bg-muted px-1 py-0.5 text-xs">
                read_project_instructions
              </code>{' '}
              tool at the start of each session. Edit it to provide
              project-specific instructions, analysis focus areas, and
              context.
            </li>
            <li>
              <strong>AI access:</strong> The AI can read any project document
              using the{' '}
              <code className="rounded bg-muted px-1 py-0.5 text-xs">
                read_project_document
              </code>{' '}
              tool. Upload scope documents, prior reports, or datasheets for
              reference during analysis.
            </li>
          </ul>
        </Section>

        <Section title="File Explorer">
          <p className="mb-3">
            Browse the extracted firmware filesystem in a tree view.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Tree navigation:</strong> Click directories to expand
              them. The tree lazy-loads contents for performance.
            </li>
            <li>
              <strong>Text files:</strong> Displayed with syntax highlighting in
              a code editor (Monaco). Use Ctrl+F to search within a file.
            </li>
            <li>
              <strong>Binary files:</strong> Shown in a hex viewer with offset,
              hex bytes, and ASCII columns.
            </li>
            <li>
              <strong>ELF binaries:</strong> Shows architecture, entry point,
              section headers, and linked libraries.
            </li>
            <li>
              <strong>File info:</strong> Each file shows its type (via
              libmagic), size, permissions, and hashes.
            </li>
          </ul>
        </Section>

        <Section title="Binary Analysis">
          <p className="mb-3">
            Analyze ELF binaries using radare2 and Ghidra integration.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Function listing:</strong> View all functions with their
              addresses and sizes, sorted by size to highlight interesting
              custom functions.
            </li>
            <li>
              <strong>Disassembly:</strong> Click a function to view its
              disassembly with annotations.
            </li>
            <li>
              <strong>Decompilation:</strong> Request pseudo-C decompilation via
              Ghidra headless for readable output. Results are cached for fast
              repeat access.
            </li>
            <li>
              <strong>Binary protections:</strong> Check NX, ASLR, stack
              canaries, RELRO, PIE, and Fortify status.
            </li>
            <li>
              <strong>Imports/Exports:</strong> View imported symbols grouped by
              library and exported symbols.
            </li>
          </ul>
        </Section>

        <Section title="AI Assistant (MCP)">
          <p className="mb-3">
            The AI assistant connects via MCP (Model Context Protocol) using
            Claude Code or Claude Desktop. It has access to 40+ tools for
            filesystem inspection, string analysis, binary analysis, security
            assessment, SBOM, emulation, and fuzzing.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Setup:</strong> Register the MCP server with your Claude
              client:
              <pre className="mt-1 rounded bg-muted px-2 py-1.5 text-xs font-mono overflow-x-auto">
                claude mcp add wairz -- docker exec -i wairz-backend-1 uv run
                wairz-mcp --project-id {'<PROJECT_ID>'}
              </pre>
            </li>
            <li>
              <strong>Project instructions:</strong> The AI reads your WAIRZ.md
              at the start of each session via the{' '}
              <code className="rounded bg-muted px-1 py-0.5 text-xs">
                read_project_instructions
              </code>{' '}
              tool. Edit WAIRZ.md from the project Overview to customize the
              AI's behavior.
            </li>
            <li>
              <strong>Tools:</strong> The AI uses tools autonomously &mdash;
              listing directories, reading files, extracting strings, analyzing
              binaries, checking security configurations, running emulation, and
              more.
            </li>
            <li>
              <strong>Findings:</strong> When the AI discovers security issues,
              it records them as formal findings using the{' '}
              <code className="rounded bg-muted px-1 py-0.5 text-xs">
                add_finding
              </code>{' '}
              tool. These appear on the Findings page.
            </li>
          </ul>
        </Section>

        <Section title="Component Map">
          <p className="mb-3">
            Visualize firmware component dependencies as an interactive graph.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Dependency graph:</strong> Shows ELF binary dependencies
              (DT_NEEDED), shell script calls, init script service mappings,
              and config-to-binary references.
            </li>
            <li>
              <strong>Node types:</strong> Color-coded by type &mdash; binaries
              (blue), libraries (purple), scripts (green), config files
              (orange), init scripts (yellow), kernel modules (red).
            </li>
            <li>
              <strong>Interaction:</strong> Pan, zoom, and click nodes for
              details. Clusters can be collapsed for large graphs.
            </li>
            <li>
              <strong>Export:</strong> Save the map as PNG, SVG, or JSON.
            </li>
          </ul>
        </Section>

        <Section title="SBOM & Vulnerability Scanning">
          <p className="mb-3">
            Generate a Software Bill of Materials and scan for known
            vulnerabilities.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>SBOM generation:</strong> Identifies software components
              using package manager databases, kernel version, library SONAME,
              binary version strings, and config file hints.
            </li>
            <li>
              <strong>Vulnerability scan:</strong> Checks identified components
              against the NVD (National Vulnerability Database) for known CVEs.
            </li>
            <li>
              <strong>Dashboard:</strong> View component counts, severity
              breakdown, and CVE details with links to NVD entries.
            </li>
            <li>
              <strong>Export:</strong> Download the SBOM in CycloneDX JSON
              format.
            </li>
            <li>
              <strong>Findings:</strong> Vulnerability scan results are
              automatically created as findings with source "sbom_scan."
            </li>
          </ul>
        </Section>

        <Section title="Emulation">
          <p className="mb-3">
            Run firmware in QEMU for dynamic analysis. Supports ARM, MIPS, and
            x86 architectures.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>User mode:</strong> Run a single binary in a chroot
              environment. Fast and good for testing specific programs.
            </li>
            <li>
              <strong>System mode:</strong> Boot the full firmware OS with a
              pre-built Linux kernel. Good for testing services and network
              behavior. Requires a matching kernel (manage via the Kernels
              panel).
            </li>
            <li>
              <strong>Terminal:</strong> Interactive terminal via xterm.js for
              running commands in the emulated environment.
            </li>
            <li>
              <strong>Session management:</strong> Start, stop, and monitor
              emulation sessions. View boot logs for troubleshooting.
            </li>
          </ul>
        </Section>

        <Section title="Fuzzing">
          <p className="mb-3">
            Automated crash discovery using AFL++ in QEMU mode.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Target analysis:</strong> Analyze a binary to assess its
              fuzzing suitability based on input handling, dangerous function
              usage, and binary protections.
            </li>
            <li>
              <strong>Campaign management:</strong> Create, start, and stop
              fuzzing campaigns. Monitor real-time stats including
              executions/sec, paths found, and crashes.
            </li>
            <li>
              <strong>Crash triage:</strong> View crash inputs, stack traces,
              and exploitability classification. Create findings directly from
              triaged crashes.
            </li>
          </ul>
        </Section>

        <Section title="Findings & Reporting">
          <p className="mb-3">
            View, manage, and export security findings from the Findings page.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Filtering:</strong> Filter by severity (critical, high,
              medium, low, info) and status (open, confirmed, false positive,
              fixed).
            </li>
            <li>
              <strong>Detail view:</strong> Click a finding to see its full
              description, evidence, affected file path, and associated CVEs.
            </li>
            <li>
              <strong>Status management:</strong> Update finding status to
              confirm, mark as false positive, or mark as fixed.
            </li>
            <li>
              <strong>Export:</strong> Generate a security assessment report in
              Markdown or PDF format. Reports include an executive summary,
              firmware info, and all findings organized by severity.
            </li>
          </ul>
        </Section>

        <Section title="Keyboard Shortcuts">
          <div className="space-y-2">
            <div className="grid grid-cols-[120px_1fr] gap-y-1.5">
              <Kbd>Ctrl + F</Kbd>
              <span>Search within the current file in the code viewer</span>
            </div>
          </div>
        </Section>
      </div>
    </div>
  )
}

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex items-center rounded border border-border bg-muted px-1.5 py-0.5 text-xs font-mono text-foreground">
      {children}
    </kbd>
  )
}
