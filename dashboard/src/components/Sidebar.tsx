import { Layout, Menu, Button, Tag } from 'antd'
import { Activity, Server, AlertTriangle, LogOut, CreditCard, Shield, Ban, CheckCircle, FileBarChart, BarChart3 } from 'lucide-react'
import { Link, useLocation } from '@tanstack/react-router'
import { useAuth } from '../context/AuthContext'
import { versionAPI } from '../api/client'
import { useEffect, useState } from 'react'

const { Sider } = Layout

interface SidebarProps {
  collapsed: boolean
  setCollapsed: (value: boolean) => void
}

const navItems = [
  { key: '/dashboard', label: 'Overview', icon: <Activity size={16} /> },
  { key: '/dashboard/servers', label: 'Servers', icon: <Server size={16} /> },
  { key: '/dashboard/threats', label: 'Threats', icon: <Shield size={16} /> },
  { key: '/dashboard/blocked-ips', label: 'Blocked IPs', icon: <Ban size={16} /> },
  { key: '/dashboard/whitelist', label: 'Whitelist', icon: <CheckCircle size={16} /> },
  { key: '/dashboard/alerts', label: 'Alerts', icon: <AlertTriangle size={16} /> },
  { key: '/dashboard/reports', label: 'Reports', icon: <FileBarChart size={16} /> },
  { key: '/dashboard/visualizer', label: 'Visualizer', icon: <BarChart3 size={16} /> },
  { key: '/subscription', label: 'Subscription', icon: <CreditCard size={16} /> },
]

export default function Sidebar({ collapsed, setCollapsed }: SidebarProps) {
  const { pathname } = useLocation()
  const { logout } = useAuth()
  const [versions, setVersions] = useState<{ version: string; agentVersion: string } | null>(null)
  
  useEffect(() => {
    versionAPI.get()
      .then(res => setVersions(res.data))
      .catch(() => setVersions({ version: '0.1.0', agentVersion: '0.4.0' }))
  }, [])
  
  // Find selected key. Assuming logic: exact match or prefix
  // Simplified for MVP: exact match usually or check startsWith
  const selectedKey = navItems.find(item => pathname === item.key || (item.key !== '/dashboard' && pathname.startsWith(item.key)))?.key || '/dashboard'

  const handleLogout = () => {
    logout()
  }

  const menuItems = navItems.map(item => ({
    key: item.key,
    icon: item.icon,
    label: <Link to={item.key}>{item.label}</Link>
  }))

  // Add logout as a non-link item/footer or just append?
  // Antd Menu doesn't easily support bottom aligned items without flex tricks.
  // We can put buttons outside the menu in the Sider.

  return (
    <Sider 
      collapsible 
      collapsed={collapsed} 
      onCollapse={(value) => setCollapsed(value)}
      breakpoint="lg"
      theme="dark"
      width={220}
      style={{ boxShadow: 'none' }}
    >
      <div style={{ margin: collapsed ? '16px 0' : 16, display: 'flex', alignItems: 'center', justifyContent: collapsed ? 'center' : 'flex-start', gap: 12 }}>
         <img 
           src="https://r2.kerneleye.net/logo_kerneleye.png" 
           alt="KernelEye" 
           style={{ height: collapsed ? 36 : 48, width: 'auto', borderRadius: 8 }} 
         />
         {!collapsed && (
           <div style={{ display: 'flex', flexDirection: 'column' }}>
             <span style={{ color: 'white', fontWeight: 'bold', fontSize: 18, lineHeight: 1.2 }}>KernelEye</span>
             <span style={{ color: 'rgba(255,255,255,0.5)', fontSize: 11, letterSpacing: 0.5, lineHeight: 1.2 }}>SECURITY MONITOR</span>
           </div>
         )}
      </div>

      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[selectedKey]}
        items={menuItems}
      />
      
      <div style={{ position: 'absolute', bottom: 50, width: '100%', borderTop: '1px solid rgba(255,255,255,0.1)', padding: collapsed ? '8px 0' : '8px 16px' }}>
        {versions && (
          <div style={{ display: 'flex', flexDirection: collapsed ? 'column' : 'row', gap: 4, justifyContent: 'center' }}>
            <Tag color="blue" style={{ margin: 0, fontSize: 10 }}>App: {versions.version}</Tag>
            {!collapsed && <Tag color="green" style={{ margin: 0, fontSize: 10 }}>Agent: {versions.agentVersion}</Tag>}
          </div>
        )}
      </div>

      <div style={{ position: 'absolute', bottom: 0, width: '100%', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
        <Button 
          type="text" 
          danger 
          block 
          style={{ height: 50, display: 'flex', alignItems: 'center', justifyContent: collapsed ? 'center' : 'flex-start', paddingLeft: collapsed ? 0 : 24 }}
          onClick={handleLogout}
          icon={<LogOut size={16} />}
        >
          {!collapsed && "Logout"}
        </Button>
      </div>
    </Sider>
  )
}
