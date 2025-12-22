import { useState, useEffect } from 'react'
import { Outlet, useLocation, Link } from '@tanstack/react-router'
import { ProLayout, PageContainer } from '@ant-design/pro-components'
import { Shield, Activity, Server, AlertTriangle, Bell, LogOut } from 'lucide-react'
import { Button, Avatar, Dropdown, Badge } from 'antd'
import type { MenuProps } from 'antd'

const menuItems = [
  {
    path: '/dashboard',
    name: 'Overview',
    icon: <Activity size={16} />,
  },
  {
    path: '/dashboard/servers',
    name: 'Servers',
    icon: <Server size={16} />,
  },
  {
    path: '/dashboard/threats',
    name: 'Threats',
    icon: <Shield size={16} />,
  },
  {
    path: '/dashboard/alerts',
    name: 'Alerts',
    icon: <AlertTriangle size={16} />,
  },
]

import { useQueryClient } from '@tanstack/react-query'
import { useWebSocket } from '../context/WebSocketContext'

export default function Dashboard() {
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(false)
  const queryClient = useQueryClient()
  const { lastMessage } = useWebSocket()

  // Determine the selected menu key based on current path
  // This fixes the issue where Overview (/dashboard) is always highlighted
  const getSelectedKey = () => {
    const pathname = location.pathname
    // Check for exact match first, then prefix match for child routes
    const matched = menuItems.find(item => 
      pathname === item.path || 
      (item.path !== '/dashboard' && pathname.startsWith(item.path))
    )
    return matched?.path || '/dashboard'
  }

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
        // For individual traffic, we might want to invalidate specific server traffic or stats
        // queryClient.invalidateQueries({ queryKey: ['serverTraffic'] })
        break
    }
  }, [lastMessage, queryClient])

  const handleLogout = () => {
    localStorage.removeItem('kerneleye_token')
    window.location.href = '/login'
  }

  const userMenuItems: MenuProps['items'] = [
    {
      key: 'logout',
      label: 'Logout',
      icon: <LogOut size={14} />,
      danger: true,
      onClick: handleLogout,
    },
  ]

  return (
    <ProLayout
      title="KernelEye"
      logo={
        <div style={{ 
          width: 32, 
          height: 32, 
          background: '#4f46e5', 
          borderRadius: 8, 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center' 
        }}>
          <Shield size={18} color="white" />
        </div>
      }
      layout="mix"
      siderWidth={220}
      collapsed={collapsed}
      onCollapse={setCollapsed}
      fixSiderbar
      fixedHeader
      route={{
        path: '/dashboard',
        routes: menuItems.map(item => ({
          path: item.path,
          name: item.name,
          icon: item.icon,
        })),
      }}
      location={{ pathname: location.pathname }}
      menuProps={{
        selectedKeys: [getSelectedKey()],
      }}
      menuItemRender={(item, dom) => (
        <Link to={item.path || '/dashboard'}>{dom}</Link>
      )}
      actionsRender={() => [
        <Badge key="notifications" count={0} size="small">
          <Button type="text" icon={<Bell size={18} />} />
        </Badge>,
        <Dropdown key="user" menu={{ items: userMenuItems }} placement="bottomRight">
          <Avatar 
            style={{ backgroundColor: '#4f46e5', cursor: 'pointer' }} 
            size="small"
          >
            U
          </Avatar>
        </Dropdown>,
      ]}
      token={{
        header: {
          colorBgHeader: '#141414',
          colorTextMenu: '#dfdfdf',
          colorTextMenuSelected: '#fff',
          colorBgMenuItemHover: 'rgba(255,255,255,0.1)',
          colorBgMenuItemSelected: 'rgba(79, 70, 229, 0.5)',
        },
        sider: {
          colorMenuBackground: '#141414',
          colorTextMenu: '#dfdfdf',
          colorTextMenuSelected: '#fff',
          colorBgMenuItemHover: 'rgba(255,255,255,0.1)',
          colorBgMenuItemSelected: 'rgba(79, 70, 229, 0.5)',
          colorTextMenuTitle: '#fff',
        },
        pageContainer: {
          colorBgPageContainer: '#0a0a0a',
        },
      }}
      bgLayoutImgList={[]}
    >
      <PageContainer
        header={{ title: false, breadcrumb: {} }}
        style={{ minHeight: '100vh' }}
      >
        <Outlet />
      </PageContainer>
    </ProLayout>
  )
}
