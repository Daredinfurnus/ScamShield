import { createBrowserRouter } from 'react-router-dom'
import Layout from './components/layout/Layout'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import NewInvestigation from './pages/NewInvestigation'
import InvestigationReport from './pages/InvestigationReport'
import EntityGraph from './pages/EntityGraph'
import InvestigationHistory from './pages/InvestigationHistory'
import About from './pages/About'

export const routes = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    children: [
      { index: true, element: <Landing /> },
      { path: 'dashboard', element: <Dashboard /> },
      { path: 'investigations/new', element: <NewInvestigation /> },
      { path: 'investigations/:id/report', element: <InvestigationReport /> },
      { path: 'investigations/:id/graph', element: <EntityGraph /> },
      { path: 'investigations/history', element: <InvestigationHistory /> },
      { path: 'about', element: <About /> },
    ],
  },
])