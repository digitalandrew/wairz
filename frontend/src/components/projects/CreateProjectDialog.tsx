import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, CheckCircle } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import FirmwareUpload from './FirmwareUpload'

type Step = 'details' | 'firmware' | 'done'

interface CreateProjectDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export default function CreateProjectDialog({ open, onOpenChange }: CreateProjectDialogProps) {
  const navigate = useNavigate()
  const { createProject, creating } = useProjectStore()

  const [step, setStep] = useState<Step>('details')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [projectId, setProjectId] = useState<string | null>(null)

  const reset = () => {
    setStep('details')
    setName('')
    setDescription('')
    setProjectId(null)
  }

  const handleClose = (v: boolean) => {
    if (!v) reset()
    onOpenChange(v)
  }

  const handleCreate = async () => {
    if (!name.trim()) return
    try {
      const project = await createProject(name.trim(), description.trim() || undefined)
      setProjectId(project.id)
      setStep('firmware')
    } catch {
      // error is set in store
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md">
        {step === 'details' && (
          <>
            <DialogHeader>
              <DialogTitle>New Project</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label htmlFor="name">Name</Label>
                <Input
                  id="name"
                  placeholder="e.g. OpenWrt 23.05"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                  autoFocus
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="desc">Description (optional)</Label>
                <Textarea
                  id="desc"
                  placeholder="Target device, firmware version, notes..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={3}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => handleClose(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={!name.trim() || creating}>
                {creating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Create Project
              </Button>
            </DialogFooter>
          </>
        )}

        {step === 'firmware' && projectId && (
          <>
            <DialogHeader>
              <DialogTitle>Upload Firmware</DialogTitle>
            </DialogHeader>
            <div className="py-2">
              <FirmwareUpload projectId={projectId} onComplete={() => setStep('done')} />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setStep('done') }}>
                Skip
              </Button>
            </DialogFooter>
          </>
        )}

        {step === 'done' && projectId && (
          <>
            <DialogHeader>
              <DialogTitle>Project Created</DialogTitle>
            </DialogHeader>
            <div className="flex flex-col items-center gap-2 py-6">
              <CheckCircle className="h-10 w-10 text-green-500" />
              <p className="text-sm text-muted-foreground">Your project is ready.</p>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => handleClose(false)}>
                Close
              </Button>
              <Button
                onClick={() => {
                  handleClose(false)
                  navigate(`/projects/${projectId}`)
                }}
              >
                Go to Project
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
