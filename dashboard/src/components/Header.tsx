import { Layout, Button, Avatar, Tag, Typography, theme } from 'antd'
import { Menu as MenuIcon, User } from 'lucide-react'
import { useLocation } from '@tanstack/react-router'

const { Header: AntHeader } = Layout
const { Title } = Typography

interface HeaderProps {
  collapsed: boolean
  setCollapsed: (value: boolean) => void
}

export default function Header({ collapsed, setCollapsed }: HeaderProps) {
  const location = useLocation()
  const {
    token: { colorBgContainer },
  } = theme.useToken()
  
  const getPageTitle = () => {
    const path = location.pathname.split('/').pop()
    const title = path && path !== 'dashboard' ? path : 'Overview'
    return title.charAt(0).toUpperCase() + title.slice(1)
  }

  return (
    <AntHeader style={{ padding: '0 24px', background: colorBgContainer, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <Button
          type="text"
          icon={<MenuIcon size={18} />}
          onClick={() => setCollapsed(!collapsed)}
          style={{
            fontSize: '16px',
            width: 32,
            height: 32,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}
        />
        <Title level={4} style={{ margin: 0, textTransform: 'capitalize' }}>{getPageTitle()}</Title>

        <Tag color="success">System Healthy</Tag>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <Avatar style={{ backgroundColor: '#4f46e5', verticalAlign: 'middle' }} icon={<User size={16} />} >U</Avatar>
      </div>
    </AntHeader>
  )
}
