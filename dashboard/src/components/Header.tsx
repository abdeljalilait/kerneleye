import { Button, Typography, Space, Tag, theme } from 'antd'
import { Bell } from 'lucide-react'
import { useLocation, useNavigate } from '@tanstack/react-router'
import { useAlerts } from '../hooks/useQueries'

const { Text } = Typography

interface HeaderProps {
  menuItems: Array<{ key: string; label: string }>
}

export default function Header({ menuItems }: HeaderProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const { data: alerts } = useAlerts()
  const { token } = theme.useToken()

  const activeAlerts = alerts?.filter(a => a.status === 'active').length || 0

  const currentLabel =
    menuItems.find(
      item =>
        location.pathname === item.key ||
        (item.key !== '/dashboard' && location.pathname.startsWith(item.key)),
    )?.label || 'Overview'

  return (
    <div
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 99,
        height: 72,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: `0 ${token.paddingXL}px`,
        backdropFilter: 'blur(12px)',
        borderBottom: `1px solid ${token.colorBorderSecondary}`,
      }}
    >
      {/* Page title */}
      <div>
        <Text style={{ fontSize: 12, color: token.colorTextTertiary, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Dashboard
        </Text>
        <Text strong style={{ fontSize: 20, display: 'block' }}>
          {currentLabel}
        </Text>
      </div>

      {/* Right actions */}
      <Space size={16}>
        {/* Alert bell */}
        <Button
          type="text"
          icon={<Bell size={20} />}
          onClick={() => navigate({ to: '/dashboard/alerts' })}
          style={{ width: 44, height: 44 }}
        >
          {activeAlerts > 0 && (
            <span
              style={{
                position: 'absolute',
                top: 4,
                right: 4,
                minWidth: 18,
                height: 18,
                borderRadius: 9,
                background: token.colorError,
                color: '#fff',
                fontSize: 11,
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '0 4px',
              }}
            >
              {activeAlerts}
            </span>
          )}
        </Button>

        {/* Status indicator */}
        <Tag
          color="success"
          style={{
            padding: '4px 14px',
            fontSize: 13,
            fontWeight: 500,
            borderRadius: 20,
          }}
        >
          System Active
        </Tag>
      </Space>
    </div>
  )
}
