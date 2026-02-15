import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import AppLayout from '@/components/layout/AppLayout'
import DisclaimerDialog from '@/components/DisclaimerDialog'
import ProjectsPage from '@/pages/ProjectsPage'
import ProjectDetailPage from '@/pages/ProjectDetailPage'
import ExplorePage from '@/pages/ExplorePage'
import FindingsPage from '@/pages/FindingsPage'
import ComponentMapPage from '@/pages/ComponentMapPage'
import SbomPage from '@/pages/SbomPage'
import HelpPage from '@/pages/HelpPage'
import NotFoundPage from '@/pages/NotFoundPage'

export default function App() {
  return (
    <BrowserRouter>
      <DisclaimerDialog />
      <Routes>
        <Route path="/" element={<Navigate to="/projects" replace />} />
        <Route element={<AppLayout />}>
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
          <Route path="/projects/:projectId/explore" element={<ExplorePage />} />
          <Route path="/projects/:projectId/findings" element={<FindingsPage />} />
          <Route path="/projects/:projectId/map" element={<ComponentMapPage />} />
          <Route path="/projects/:projectId/sbom" element={<SbomPage />} />
          <Route path="/help" element={<HelpPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
