import { Button, Badge, Typography } from 'antd'
import { Bell } from 'lucide-react'
import { useLocation } from '@tanstack/react-router'

const { Text } = Typography

interface HeaderProps {
  menuItems: Array<{ key: string; label: string }>
}

export default function Header({ menuItems }: HeaderProps) {
  const location = useLocation()

  const getSelectedKey = () => {
    const pathname = location.pathname
    const matched = menuItems.find(item => 
      pathname === item.key || 
      (item.key !== '/dashboard' && pathname.startsWith(item.key))
    )
    return matched?.key || '/dashboard'
  }

  return (
    <div
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
    </div>
  )
}
