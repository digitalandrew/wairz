import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'

const DISCLAIMER_KEY = 'wairz-disclaimer-acknowledged'

export default function DisclaimerDialog() {
  const [open, setOpen] = useState(() => !sessionStorage.getItem(DISCLAIMER_KEY))

  function handleAcknowledge() {
    sessionStorage.setItem(DISCLAIMER_KEY, '1')
    setOpen(false)
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleAcknowledge() }}>
      <DialogContent showCloseButton={false} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-xl">Welcome to WAIRZ</DialogTitle>
          <DialogDescription asChild>
            <div className="space-y-3 pt-2 text-sm leading-relaxed">
              <p>
                WAIRZ is an AI-assisted firmware security analysis tool designed for
                <strong> ethical security research</strong> and <strong>firmware hardening</strong>.
              </p>
              <div className="rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2">
                <p className="text-yellow-700 dark:text-yellow-300">
                  This tool is still in <strong>Beta</strong>. AI-generated findings may contain
                  inaccuracies or false positives.
                </p>
              </div>
              <p className="font-medium text-foreground">
                Please do not contribute to AI slop in bug bounty or CVE reporting. Always
                thoroughly review and manually confirm any vulnerabilities yourself before
                reporting.
              </p>
            </div>
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="pt-2">
          <Button onClick={handleAcknowledge} className="w-full sm:w-auto">
            I Understand
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
