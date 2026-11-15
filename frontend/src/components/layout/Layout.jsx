import { Outlet } from 'react-router-dom'
import { Navbar } from './Navbar'
import { Sidebar } from './Sidebar'
import { Footer } from './Footer'

export default function Layout() {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <div className="flex-1 flex w-full max-w-[1600px] mx-auto px-3 sm:px-5 lg:px-8">
        <Sidebar />
        <main className="flex-1 min-w-0 py-6 sm:py-8 lg:pl-7">
          <Outlet />
        </main>
      </div>
      <Footer />
    </div>
  )
}
