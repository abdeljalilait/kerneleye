import { useState, useEffect, useMemo } from 'react'
import { Outlet, useLocation, Link, useNavigate } from '@tanstack/react-router'
import { Layout, Menu, Button, Avatar, Dropdown, Badge, Typography } from 'antd'
import Header from '../components/Header'
import { 
  Shield, 
  LayoutDashboard,
  Server, 
  AlertTriangle, 
  LogOut, 
  ChevronLeft,
  ChevronRight,
  User,
  CreditCard,
  FileText,
  BarChart3,
  Ban,
  CheckCircle
} from 'lucide-react'
import type { MenuProps } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
import { useWebSocket } from '../context/WebSocketContext'

const { Sider, Content } = Layout
const { Text } = Typography

const mainMenuItems = [
  {
    key: '/dashboard',
    icon: <LayoutDashboard size={18} />,
    label: 'Overview',
  },
  {
    key: '/dashboard/servers',
    icon: <Server size={18} />,
    label: 'Servers',
  },
  {
    key: '/dashboard/threats',
    icon: <Shield size={18} />,
    label: 'Threats',
  },
  {
    key: '/dashboard/blocked-ips',
    icon: <Ban size={18} />,
    label: 'Blocked IPs',
  },
  {
    key: '/dashboard/whitelist',
    icon: <CheckCircle size={18} />,
    label: 'Whitelist',
  },
  {
    key: '/dashboard/alerts',
    icon: <AlertTriangle size={18} />,
    label: 'Alerts',
  },
]

const analyticsMenuItems = [
  {
    key: '/dashboard/reports',
    icon: <FileText size={18} />,
    label: 'Reports',
  },
  {
    key: '/dashboard/visualizer',
    icon: <BarChart3 size={18} />,
    label: 'Visualizer',
  },
]

export default function Dashboard() {
  const location = useLocation()
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(false)
  const queryClient = useQueryClient()
  const { lastMessage } = useWebSocket()

  // React to WebSocket messages
  useEffect(() => {
    if (!lastMessage) return

    switch (lastMessage.type) {
      case 'new_server':
      case 'server_updated':
        queryClient.invalidateQueries({ queryKey: ['servers'] })
        break
      case 'new_threat':
        queryClient.invalidateQueries({ queryKey: ['threats'] })
        break
      case 'new_alert':
        queryClient.invalidateQueries({ queryKey: ['alerts'] })
        break
      case 'new_traffic':
        break
    }
  }, [lastMessage, queryClient])

  const getSelectedKey = () => {
    const pathname = location.pathname
    const allItems = [...mainMenuItems, ...analyticsMenuItems]
    const matched = allItems.find(item => 
      pathname === item.key || 
      (item.key !== '/dashboard' && pathname.startsWith(item.key))
    )
    return matched?.key || '/dashboard'
  }

  const handleLogout = () => {
    localStorage.removeItem('kerneleye_token')
    window.location.href = '/login'
  }

  const userMenuItems: MenuProps['items'] = [
    {
      key: 'profile',
      label: 'Profile & Settings',
      icon: <User size={14} />,
      onClick: () => navigate({ to: '/dashboard/profile' }),
    },
    {
      key: 'subscription',
      label: 'Subscription',
      icon: <CreditCard size={14} />,
      onClick: () => navigate({ to: '/dashboard/subscription' }),
    },
    {
      type: 'divider',
    },
    {
      key: 'logout',
      label: 'Logout',
      icon: <LogOut size={14} />,
      danger: true,
      onClick: handleLogout,
    },
  ]

  const menuItemsMapped = useMemo(() => mainMenuItems.map(item => ({
    key: item.key,
    icon: item.icon,
    label: <Link to={item.key} style={{ textDecoration: 'none' }}>{item.label}</Link>,
  })), [])

  const analyticsItemsMapped = useMemo(() => analyticsMenuItems.map(item => ({
    key: item.key,
    icon: item.icon,
    label: <Link to={item.key} style={{ textDecoration: 'none' }}>{item.label}</Link>,
  })), [])

  return (
    <Layout style={{ minHeight: '100vh', background: 'var(--bg-primary)' }}>
      {/* Sidebar */}
      <Sider
        trigger={null}
        collapsible
        collapsed={collapsed}
        collapsedWidth={80}
        width={260}
        style={{
          background: 'var(--glass-bg)',
          backdropFilter: 'blur(20px)',
          borderRight: '1px solid var(--glass-border)',
          position: 'fixed',
          left: 0,
          top: 0,
          bottom: 0,
          zIndex: 100,
          boxShadow: '4px 0 24px rgba(0, 0, 0, 0.3)',
        }}
      >
        {/* Logo */}
        <div 
          style={{ 
            height: 80, 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: collapsed ? 'center' : 'flex-start',
            padding: collapsed ? 0 : '0 24px',
            gap: 12,
            borderBottom: '1px solid var(--glass-border)',
          }}
        >
          <img 
            src="https://r2.kerneleye.net/logo_kerneleye.png" 
            alt="KernelEye" 
            style={{ height: collapsed ? 36 : 44, width: 'auto', borderRadius: 8, flexShrink: 0 }} 
          />
          {!collapsed && (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <Text strong style={{ fontSize: 20, color: 'var(--text-primary)', lineHeight: 1.2 }}>
                KernelEye
              </Text>
              <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>
                SECURITY MONITOR
              </Text>
            </div>
          )}
        </div>

        {/* Main Navigation */}
        <div style={{ padding: '16px 12px' }}>
          <Text 
            style={{ 
              fontSize: 11, 
              color: 'var(--text-tertiary)', 
              letterSpacing: '0.1em',
              marginLeft: collapsed ? 0 : 12,
              marginBottom: 8,
              display: collapsed ? 'none' : 'block',
              fontWeight: 600,
            }}
          >
            MAIN
          </Text>
          <Menu
            mode="inline"
            selectedKeys={[getSelectedKey()]}
            inlineCollapsed={collapsed}
            style={{
              background: 'transparent',
              border: 'none',
            }}
            items={menuItemsMapped}
          />
        </div>

        {/* Analytics Navigation */}
        <div style={{ padding: '0 12px' }}>
          <Text 
            style={{ 
              fontSize: 11, 
              color: 'var(--text-tertiary)', 
              letterSpacing: '0.1em',
              marginLeft: collapsed ? 0 : 12,
              marginBottom: 8,
              display: collapsed ? 'none' : 'block',
              fontWeight: 600,
            }}
          >
            ANALYTICS
          </Text>
          <Menu
            mode="inline"
            selectedKeys={[getSelectedKey()]}
            inlineCollapsed={collapsed}
            style={{
              background: 'transparent',
              border: 'none',
            }}
            items={analyticsItemsMapped}
          />
        </div>

        {/* Collapse Button */}
        <div 
          style={{ 
            position: 'absolute',
            bottom: 80,
            left: 0,
            right: 0,
            padding: '0 16px',
            display: 'flex',
            justifyContent: 'center',
          }}
        >
          <Button
            type="text"
            icon={collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
            onClick={() => setCollapsed(!collapsed)}
            style={{
              color: 'var(--text-tertiary)',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 8,
              width: collapsed ? 40 : '100%',
              height: 36,
            }}
          >
            {!collapsed && <span style={{ marginLeft: 8 }}>Collapse</span>}
          </Button>
        </div>

        {/* User Section */}
        <div 
          style={{ 
            position: 'absolute',
            bottom: 0,
            left: 0,
            right: 0,
            padding: '16px',
            borderTop: '1px solid var(--glass-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'flex-start',
            gap: 12,
          }}
        >
          <Dropdown menu={{ items: userMenuItems }} placement="topRight" arrow>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }}>
              <Badge
                dot
                color="var(--success)"
                offset={[-4, 32]}
              >
                <Avatar
                  style={{
                    background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                    width: 40,
                    height: 40,
                  }}
                >
                  <User size={18} />
                </Avatar>
              </Badge>
              {!collapsed && (
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <Text strong style={{ color: 'var(--text-primary)', fontSize: 14, lineHeight: 1.3 }}>
                    Administrator
                  </Text>
                  <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, lineHeight: 1.3 }}>
                    Online
                  </Text>
                </div>
              )}
            </div>
          </Dropdown>
        </div>
      </Sider>

      {/* Main Layout */}
      <Layout 
        style={{ 
          marginLeft: collapsed ? 80 : 260,
          transition: 'margin-left 0.3s ease',
          background: 'var(--bg-primary)',
          minHeight: '100vh',
        }}
      >
        {/* Header */}
        <Header menuItems={[...mainMenuItems, ...analyticsMenuItems]} />

        {/* Main Content */}
        <Content
          style={{
            padding: '32px',
            background: 'var(--bg-primary)',
            position: 'relative',
          }}
        >
          {/* Background Effects */}
          <div 
            style={{
              position: 'fixed',
              top: '10%',
              right: '5%',
              width: 400,
              height: 400,
              background: 'radial-gradient(circle, rgba(99, 102, 241, 0.08) 0%, transparent 70%)',
              pointerEvents: 'none',
              zIndex: 0,
            }}
          />
          <div 
            style={{
              position: 'fixed',
              bottom: '10%',
              left: collapsed ? '15%' : '25%',
              width: 300,
              height: 300,
              background: 'radial-gradient(circle, rgba(6, 182, 212, 0.06) 0%, transparent 70%)',
              pointerEvents: 'none',
              zIndex: 0,
            }}
          />

          {/* Content Outlet */}
          <div style={{ position: 'relative', zIndex: 1, maxWidth: 1600, margin: '0 auto' }}>
            <Outlet />
          </div>
        </Content>
      </Layout>
    </Layout>
  )
}
