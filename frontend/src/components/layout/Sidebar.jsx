import { NavLink } from 'react-router-dom'
import { LayoutDashboard, ScanSearch, History, Network, Info, ChevronRight } from 'lucide-react'

const links = [
  { to:'/dashboard', label:'Command Center', code:'01', icon:LayoutDashboard },
  { to:'/investigations/new', label:'New Investigation', code:'02', icon:ScanSearch },
  { to:'/investigations/history', label:'Case Archive', code:'03', icon:History },
  { to:'/about', label:'System Intel', code:'04', icon:Info },
]
export function Sidebar() {
  return (
    <aside className="hidden lg:flex w-[230px] shrink-0 flex-col border-r border-cyan-300/10 py-7 pr-5">
      <div className="mb-4 px-3 cyber-kicker">Navigation / Main</div>
      <nav className="space-y-1">
        {links.map(({to,label,code,icon:Icon}) => (
          <NavLink key={to} to={to} className={({isActive}) =>
            `group flex items-center gap-3 px-3 py-3 border transition-all ${isActive ? 'border-[#b7ff38]/30 bg-[#b7ff38]/[.07] text-[#b7ff38] shadow-[inset_2px_0_0_#b7ff38]' : 'border-transparent text-slate-400 hover:text-slate-100 hover:bg-white/[.035]'}`
          }>
            <span className="font-mono-tech text-[9px] text-slate-600">{code}</span>
            <Icon size={16}/>
            <span className="text-[11px] font-mono-tech tracking-wide">{label}</span>
            <ChevronRight size={13} className="ml-auto opacity-0 group-[.active]:opacity-100"/>
          </NavLink>
        ))}
      </nav>
      <div className="mt-auto p-3 border border-cyan-300/10 bg-cyan-300/[.025]">
        <div className="flex items-center gap-2 cyber-kicker"><span className="w-1.5 h-1.5 rounded-full bg-[#b7ff38]"/> Environment</div>
        <div className="mt-3 font-mono-tech text-[10px] text-slate-300">SCAMSHIELD / DEV</div>
        <div className="mt-1 font-mono-tech text-[9px] text-slate-600">BUILD CHANNEL: LOCAL</div>
      </div>
    </aside>
  )
}
