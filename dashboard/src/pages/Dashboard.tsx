import { useState, useEffect } from 'react'
import { Outlet, useLocation, Link } from '@tanstack/react-router'
import { Layout, Menu, Button, Avatar, Dropdown, Badge, Typography } from 'antd'
import { 
  Shield, 
  Activity, 
  Server, 
  AlertTriangle, 
  Bell, 
  LogOut, 
  Settings,
  ChevronLeft,
  ChevronRight,
  User,
  CreditCard,
  FileBarChart,
  BarChart3
} from 'lucide-react'
import type { MenuProps } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
import { useWebSocket } from '../context/WebSocketContext'

const { Sider, Header, Content } = Layout
const { Text } = Typography

const menuItems = [
  {
    key: '/dashboard',
    icon: <Activity size={18} />,
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
    key: '/dashboard/alerts',
    icon: <AlertTriangle size={18} />,
    label: 'Alerts',
  },
  {
    key: '/reports',
    icon: <FileBarChart size={18} />,
    label: 'Reports',
  },
  {
    key: '/visualizer',
    icon: <BarChart3 size={18} />,
    label: 'Visualizer',
  },
]

export default function Dashboard() {
  const location = useLocation()
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
    const matched = menuItems.find(item => 
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
      onClick: () => navigate({ to: '/profile' }),
    },
    {
      key: 'subscription',
      label: 'Subscription',
      icon: <CreditCard size={14} />,
      onClick: () => navigate({ to: '/subscription' }),
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
          <div 
            style={{ 
              width: 44, 
              height: 44, 
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              borderRadius: 12,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 4px 14px rgba(99, 102, 241, 0.4)',
              flexShrink: 0,
            }}
          >
            <Shield size={24} color="white" />
          </div>
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

        {/* Navigation */}
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
            NAVIGATION
          </Text>
          <Menu
            mode="inline"
            selectedKeys={[getSelectedKey()]}
            inlineCollapsed={collapsed}
            style={{
              background: 'transparent',
              border: 'none',
            }}
            items={menuItems.map(item => ({
              key: item.key,
              icon: item.icon,
              label: <Link to={item.key} style={{ textDecoration: 'none' }}>{item.label}</Link>,
            }))}
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
        <Header
          style={{
            background: 'var(--glass-bg)',
            backdropFilter: 'blur(20px)',
            borderBottom: '1px solid var(--glass-border)',
            position: 'sticky',
            top: 0,
            zIndex: 99,
            height: 80,
            padding: '0 32px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          {/* Breadcrumb / Page Title */}
          <div>
            <Text style={{ 
              fontSize: 12, 
              color: 'var(--text-tertiary)', 
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
            }}>
              Dashboard
            </Text>
            <Text strong style={{ 
              fontSize: 20, 
              color: 'var(--text-primary)', 
              display: 'block',
              marginTop: 2,
            }}>
              {menuItems.find(item => item.key === getSelectedKey())?.label || 'Overview'}
            </Text>
          </div>

          {/* Right Actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            {/* Notification Bell */}
            <Badge count={0} size="small" style={{ background: 'var(--accent-rose)' }}>
              <Button
                type="text"
                icon={<Bell size={20} />}
                style={{
                  color: 'var(--text-secondary)',
                  width: 44,
                  height: 44,
                  borderRadius: 12,
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--border-subtle)',
                }}
              />
            </Badge>

            {/* Status Indicator */}
            <div 
              style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: 8,
                padding: '8px 16px',
                background: 'rgba(16, 185, 129, 0.1)',
                borderRadius: 20,
                border: '1px solid rgba(16, 185, 129, 0.2)',
              }}
            >
              <span 
                className="status-indicator status-online animate-pulse" 
                style={{ width: 8, height: 8 }}
              />
              <Text style={{ color: 'var(--success)', fontSize: 13, fontWeight: 500 }}>
                System Active
              </Text>
            </div>
          </div>
        </Header>

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
