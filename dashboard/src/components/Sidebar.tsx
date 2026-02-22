import { Layout, Menu, Button } from 'antd'
import { Activity, Server, AlertTriangle, LogOut, CreditCard } from 'lucide-react'
import { Link, useLocation } from '@tanstack/react-router'
import { useAuth } from '../context/AuthContext'
import logo from '../../logo_kerneleye_dark.png'

const { Sider } = Layout

interface SidebarProps {
  collapsed: boolean
  setCollapsed: (value: boolean) => void
}

const navItems = [
  { key: '/dashboard', label: 'Overview', icon: <Activity size={16} /> },
  { key: '/dashboard/servers', label: 'Servers', icon: <Server size={16} /> },
  { key: '/dashboard/threats', label: 'Threats', icon: <Shield size={16} /> },
  { key: '/dashboard/alerts', label: 'Alerts', icon: <AlertTriangle size={16} /> },
  { key: '/subscription', label: 'Subscription', icon: <CreditCard size={16} /> },
]

export default function Sidebar({ collapsed, setCollapsed }: SidebarProps) {
  const { pathname } = useLocation()
  const { logout } = useAuth()
  
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
      <div style={{ height: 64, margin: 16, display: 'flex', alignItems: 'center', justifyContent: collapsed ? 'center' : 'flex-start', gap: 12 }}>
         <img 
           src={logo} 
           alt="KernelEye" 
           style={{ height: 32, width: 'auto' }} 
         />
         {!collapsed && (
           <span style={{ color: 'white', fontWeight: 'bold', fontSize: 16 }}>KernelEye</span>
         )}
      </div>

      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[selectedKey]}
        items={menuItems}
      />
      
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
