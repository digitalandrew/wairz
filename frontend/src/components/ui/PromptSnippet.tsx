import { useState, useCallback } from 'react'
import { Copy, Check } from 'lucide-react'

interface PromptSnippetProps {
  label: string
  prompt: string
  context?: string
}

export default function PromptSnippet({ label, prompt, context }: PromptSnippetProps) {
  const [copied, setCopied] = useState(false)

  const fullPrompt = context ? prompt.replace(/\{context\}/g, context) : prompt

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(fullPrompt)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback for older browsers
      const ta = document.createElement('textarea')
      ta.value = fullPrompt
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }, [fullPrompt])

  return (
    <button
      onClick={handleCopy}
      className="group flex w-full items-center gap-2 rounded-md border border-border bg-muted/30 px-3 py-2 text-left text-xs transition-colors hover:border-primary/40 hover:bg-muted/50"
    >
      <span className="min-w-0 flex-1 truncate text-muted-foreground group-hover:text-foreground">
        {label}
      </span>
      {copied ? (
        <Check className="h-3.5 w-3.5 shrink-0 text-green-500" />
      ) : (
        <Copy className="h-3.5 w-3.5 shrink-0 text-muted-foreground group-hover:text-foreground" />
      )}
    </button>
  )
}
