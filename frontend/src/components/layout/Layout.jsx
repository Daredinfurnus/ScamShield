import { Outlet } from 'react-router-dom'
import { Navbar } from './Navbar'
import { Sidebar } from './Sidebar'
import { Footer } from './Footer'

export default function Layout() {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <div className="flex-1 flex max-w-7xl mx-auto px-4 w-full">
        <Sidebar />
        <main className="flex-1 py-8 w-full">
          <Outlet />
        </main>
      </div>
      <Footer />
    </div>
  )
}