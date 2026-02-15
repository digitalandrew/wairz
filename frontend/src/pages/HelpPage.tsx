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
            (Overview, File Explorer, Findings).
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
              Overview page. This removes the project, firmware data, findings,
              and conversations.
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
              <strong>WAIRZ.md:</strong> A special document that provides
              project-specific instructions to the AI assistant. Edit it to
              guide the AI's focus and methodology.
            </li>
            <li>
              <strong>File Explorer viewing:</strong> Documents appear in the
              file explorer and can be viewed inline.
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

        <Section title="AI Chat Assistant">
          <p className="mb-3">
            The AI assistant (powered by Claude) can analyze firmware using
            built-in tools for file inspection, string analysis, binary
            analysis, and security assessment.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Starting a conversation:</strong> Open the chat panel from
              the File Explorer or Findings page. Each conversation is saved and
              can be resumed.
            </li>
            <li>
              <strong>Model selection:</strong> Choose between available Claude
              models depending on your analysis needs.
            </li>
            <li>
              <strong>Tool calls:</strong> The AI uses tools automatically
              (listing directories, reading files, extracting strings, checking
              protections, etc.). Tool calls appear as collapsible blocks in the
              chat &mdash; expand them to see inputs and outputs.
            </li>
            <li>
              <strong>Streaming:</strong> Responses stream in real-time so you
              can follow the AI's reasoning as it works.
            </li>
            <li>
              <strong>Findings:</strong> When the AI discovers security issues,
              it can record them as formal findings using the{' '}
              <code className="rounded bg-muted px-1 py-0.5 text-xs">
                add_finding
              </code>{' '}
              tool.
            </li>
          </ul>
        </Section>

        <Section title="Autonomous Security Review">
          <p className="mb-3">
            Run comprehensive automated security reviews using multiple
            specialized AI agents.
          </p>
          <ul className="list-inside list-disc space-y-1">
            <li>
              <strong>Review categories:</strong> Select from categories like
              hardcoded credentials, binary protections, network services, file
              permissions, crypto material, and more.
            </li>
            <li>
              <strong>Multi-agent:</strong> Multiple AI agents work in parallel,
              each focused on a specific review category.
            </li>
            <li>
              <strong>Monitoring:</strong> Track progress of each agent in
              real-time from the review panel.
            </li>
            <li>
              <strong>Results:</strong> Findings from autonomous reviews appear
              in the Findings page alongside manually-created and chat-created
              findings.
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
              <Kbd>Shift + Enter</Kbd>
              <span>Insert a newline in the chat input</span>
              <Kbd>Enter</Kbd>
              <span>Send a chat message</span>
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
