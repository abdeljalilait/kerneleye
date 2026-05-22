import { useState, useEffect, useMemo } from 'react'
import { Outlet, useLocation, Link, useNavigate } from '@tanstack/react-router'
import { Layout, Menu, Button, Avatar, Dropdown, Typography, Space, theme } from 'antd'
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
  CheckCircle,
} from 'lucide-react'
import type { MenuProps } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
import { useWebSocket } from '../context/WebSocketContext'
import Header from '../components/Header'

const { Sider, Content } = Layout
const { Text } = Typography

const mainMenuItems = [
  { key: '/dashboard', icon: <LayoutDashboard size={18} />, label: 'Overview' },
  { key: '/dashboard/servers', icon: <Server size={18} />, label: 'Servers' },
  { key: '/dashboard/threats', icon: <Shield size={18} />, label: 'Threats' },
  { key: '/dashboard/blocked-ips', icon: <Ban size={18} />, label: 'Blocked IPs' },
  { key: '/dashboard/whitelist', icon: <CheckCircle size={18} />, label: 'Whitelist' },
  { key: '/dashboard/alerts', icon: <AlertTriangle size={18} />, label: 'Alerts' },
]

const analyticsMenuItems = [
  { key: '/dashboard/reports', icon: <FileText size={18} />, label: 'Reports' },
  { key: '/dashboard/visualizer', icon: <BarChart3 size={18} />, label: 'Visualizer' },
]

export default function Dashboard() {
  const location = useLocation()
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(false)
  const queryClient = useQueryClient()
  const { lastMessage } = useWebSocket()
  const { token } = theme.useToken()

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
    }
  }, [lastMessage, queryClient])

  const getSelectedKey = () => {
    const pathname = location.pathname
    const allItems = [...mainMenuItems, ...analyticsMenuItems]
    const matched = allItems.find(
      item => pathname === item.key || (item.key !== '/dashboard' && pathname.startsWith(item.key)),
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
    { type: 'divider' },
    {
      key: 'logout',
      label: 'Logout',
      icon: <LogOut size={14} />,
      danger: true,
      onClick: handleLogout,
    },
  ]

  // Build menu items with Links for proper routing
  const mainItems: MenuProps['items'] = useMemo(
    () =>
      mainMenuItems.map(item => ({
        key: item.key,
        icon: item.icon,
        label: <Link to={item.key}>{item.label}</Link>,
      })),
    [],
  )

  const analyticsItems: MenuProps['items'] = useMemo(
    () =>
      analyticsMenuItems.map(item => ({
        key: item.key,
        icon: item.icon,
        label: <Link to={item.key}>{item.label}</Link>,
      })),
    [],
  )

  const selectedKey = getSelectedKey()

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {/* Sidebar */}
      <Sider
        trigger={null}
        collapsible
        collapsed={collapsed}
        collapsedWidth={80}
        width={260}
        style={{
          position: 'fixed',
          left: 0,
          top: 0,
          bottom: 0,
          zIndex: 100,
          overflow: 'auto',
          borderRight: `1px solid ${token.colorBorderSecondary}`,
        }}
      >
        {/* Logo area */}
        <div
          style={{
            height: 80,
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'flex-start',
            padding: collapsed ? 0 : `0 ${token.paddingLG}px`,
            gap: 12,
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
          }}
        >
          <img
            src="https://r2.kerneleye.net/logo_kerneleye.png"
            alt="KernelEye"
            style={{ height: collapsed ? 36 : 40, width: 'auto', borderRadius: 8, flexShrink: 0 }}
          />
          {!collapsed && (
            <div>
              <Text strong style={{ fontSize: 18, lineHeight: 1.2 }}>
                KernelEye
              </Text>
              <br />
              <Text style={{ fontSize: 10, color: token.colorTextTertiary, letterSpacing: '0.1em' }}>
                SECURITY MONITOR
              </Text>
            </div>
          )}
        </div>

        {/* Main Navigation */}
        <div style={{ padding: `${token.padding}px ${token.paddingSM}px 0` }}>
          {!collapsed && (
            <Text
              style={{
                fontSize: 11,
                color: token.colorTextQuaternary,
                fontWeight: 600,
                letterSpacing: '0.1em',
                paddingLeft: token.paddingSM,
                marginBottom: 4,
                display: 'block',
              }}
            >
              MAIN
            </Text>
          )}
          <Menu mode="inline" selectedKeys={[selectedKey]} inlineCollapsed={collapsed} items={mainItems} />
        </div>

        {/* Analytics Navigation */}
        <div style={{ padding: `0 ${token.paddingSM}px` }}>
          {!collapsed && (
            <Text
              style={{
                fontSize: 11,
                color: token.colorTextQuaternary,
                fontWeight: 600,
                letterSpacing: '0.1em',
                paddingLeft: token.paddingSM,
                marginBottom: 4,
                display: 'block',
              }}
            >
              ANALYTICS
            </Text>
          )}
          <Menu mode="inline" selectedKeys={[selectedKey]} inlineCollapsed={collapsed} items={analyticsItems} />
        </div>

        {/* Collapse toggle */}
        <div
          style={{
            position: 'absolute',
            bottom: 80,
            left: 0,
            right: 0,
            padding: `0 ${token.padding}px`,
            display: 'flex',
            justifyContent: 'center',
          }}
        >
          <Button
            type="text"
            icon={collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
            onClick={() => setCollapsed(!collapsed)}
            style={{ width: collapsed ? 40 : '100%', height: 36 }}
          >
            {!collapsed && 'Collapse'}
          </Button>
        </div>

        {/* User section at bottom */}
        <div
          style={{
            position: 'absolute',
            bottom: 0,
            left: 0,
            right: 0,
            padding: token.padding,
            borderTop: `1px solid ${token.colorBorderSecondary}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'flex-start',
            gap: 12,
          }}
        >
          <Dropdown menu={{ items: userMenuItems }} placement="topRight" arrow>
            <Space style={{ cursor: 'pointer' }}>
              <Avatar
                size={40}
                style={{
                  background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                }}
                icon={<User size={18} />}
              />
              {!collapsed && (
                <div>
                  <Text strong style={{ fontSize: 14, lineHeight: 1.3, display: 'block' }}>
                    Administrator
                  </Text>
                  <Text style={{ color: token.colorTextTertiary, fontSize: 12 }}>
                    Online
                  </Text>
                </div>
              )}
            </Space>
          </Dropdown>
        </div>
      </Sider>

      {/* Main content area */}
      <Layout
        style={{
          marginLeft: collapsed ? 80 : 260,
          transition: 'margin-left 0.2s ease',
          minHeight: '100vh',
        }}
      >
        <Header menuItems={[...mainMenuItems, ...analyticsMenuItems]} />

        <Content style={{ padding: token.paddingXL, maxWidth: 1600, margin: '0 auto', width: '100%' }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
