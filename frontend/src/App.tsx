import { useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { Sidebar } from './components/Sidebar'
import { Navbar } from './components/Navbar'
import { Dashboard } from './pages/Dashboard'
import { Assets } from './pages/Assets'
import { Vulnerabilities } from './pages/Vulnerabilities'
import { Alerts } from './pages/Alerts'
import { Login } from './pages/Login'
import { Landing } from './pages/Landing'
import { OperationsPage } from './pages/OperationsPage'
import './App.css'

const appRoutes = [
  { path: '/', element: <Dashboard /> },
  { path: '/assets', element: <Assets /> },
  { path: '/vulnerabilities', element: <Vulnerabilities /> },
  { path: '/alerts', element: <Alerts /> },
  { path: '/incidents', element: <OperationsPage type="incidents" /> },
  { path: '/risks', element: <OperationsPage type="risks" /> },
  { path: '/compliance', element: <OperationsPage type="compliance" /> },
  { path: '/assistant', element: <OperationsPage type="assistant" /> },
  { path: '/reports', element: <OperationsPage type="reports" /> },
  { path: '/audit-logs', element: <OperationsPage type="audit" /> },
  { path: '/users', element: <OperationsPage type="users" /> },
]

function ProtectedApp() {
  const { isAuthenticated } = useAuth()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(false)
  const [timeRange, setTimeRange] = useState('7d')
  const [commandOpen, setCommandOpen] = useState(false)

  if (!isAuthenticated) return <Navigate to="/login" replace />

  return (
    <div className="app-shell">
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />
      <div className={`app-main ${collapsed ? 'app-main-collapsed' : ''}`}>
        <Navbar
          onOpenCommandPalette={() => setCommandOpen(true)}
          timeRange={timeRange}
          setTimeRange={setTimeRange}
        />
        <main className="app-content">
          <div className="breadcrumb-row">
            <span>CyberShield</span><span>/</span><strong>{pageLabel(location.pathname)}</strong>
          </div>
          <Routes>
            {appRoutes.map((route) => <Route key={route.path} path={route.path} element={route.element} />)}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
      {commandOpen && <CommandOverlay onClose={() => setCommandOpen(false)} />}
    </div>
  )
}

function CommandOverlay({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const destinations = [
    ['Security overview', '/'], ['Asset inventory', '/assets'], ['Vulnerabilities', '/vulnerabilities'],
    ['Alerts & events', '/alerts'], ['Incident investigation', '/incidents'], ['Risk register', '/risks'],
    ['Compliance & audits', '/compliance'], ['Investigation assistant', '/assistant'], ['Reports & audit history', '/reports'],
  ].filter(([name]) => name.toLowerCase().includes(query.toLowerCase()))

  return <div className="command-backdrop" onClick={onClose}>
    <div className="command-dialog" onClick={(event) => event.stopPropagation()}>
      <input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CyberShield..." />
      <div className="command-results">
        {destinations.map(([name, path]) => <button key={path} onClick={() => { navigate(path); onClose() }}>{name}<span>↵</span></button>)}
        {!destinations.length && <p>No destinations found.</p>}
      </div>
    </div>
  </div>
}

function pageLabel(path: string) {
  if (path === '/') return 'Security overview'
  return path.slice(1).split('-').map((part) => part[0].toUpperCase() + part.slice(1)).join(' ')
}

function AppRoutes() {
  return <Routes>
    <Route path="/landing" element={<Landing />} />
    <Route path="/login" element={<Login />} />
    <Route path="/*" element={<ProtectedApp />} />
  </Routes>
}

export default function App() {
  return <BrowserRouter><AuthProvider><AppRoutes /></AuthProvider></BrowserRouter>
}
