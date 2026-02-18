import { Card, Statistic, Typography } from 'antd'
import { LucideIcon } from 'lucide-react'
import { ArrowUpOutlined, ArrowDownOutlined, MinusOutlined } from '@ant-design/icons'

const { Text } = Typography

interface StatCardProps {
  title: string
  value: string
  subtext: string
  icon: LucideIcon
  trend?: 'up' | 'down' | 'neutral'
  color?: 'primary' | 'success' | 'warning' | 'error' | 'cyan'
}

const colorSchemes = {
  primary: {
    gradient: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
    glow: '0 8px 32px rgba(99, 102, 241, 0.3)',
    iconBg: 'rgba(99, 102, 241, 0.15)',
    iconColor: '#818cf8',
  },
  success: {
    gradient: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
    glow: '0 8px 32px rgba(16, 185, 129, 0.3)',
    iconBg: 'rgba(16, 185, 129, 0.15)',
    iconColor: '#34d399',
  },
  warning: {
    gradient: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
    glow: '0 8px 32px rgba(245, 158, 11, 0.3)',
    iconBg: 'rgba(245, 158, 11, 0.15)',
    iconColor: '#fbbf24',
  },
  error: {
    gradient: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
    glow: '0 8px 32px rgba(239, 68, 68, 0.3)',
    iconBg: 'rgba(239, 68, 68, 0.15)',
    iconColor: '#f87171',
  },
  cyan: {
    gradient: 'linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)',
    glow: '0 8px 32px rgba(6, 182, 212, 0.3)',
    iconBg: 'rgba(6, 182, 212, 0.15)',
    iconColor: '#22d3ee',
  },
}

export default function StatCard({ 
  title, 
  value, 
  subtext, 
  icon: Icon, 
  trend,
  color = 'primary'
}: StatCardProps) {
  const scheme = colorSchemes[color]
  
  let trendIcon = <MinusOutlined />
  let trendColor = 'var(--text-tertiary)'
  let trendBg = 'rgba(255, 255, 255, 0.05)'

  if (trend === 'up') {
    trendIcon = <ArrowUpOutlined />
    trendColor = color === 'success' ? 'var(--success)' : color === 'error' ? 'var(--error)' : '#10b981'
    trendBg = color === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(16, 185, 129, 0.1)'
  } else if (trend === 'down') {
    trendIcon = <ArrowDownOutlined />
    trendColor = color === 'success' ? 'var(--error)' : color === 'error' ? 'var(--success)' : '#ef4444'
    trendBg = 'rgba(239, 68, 68, 0.1)'
  }

  return (
    <Card
      variant="borderless"
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        backdropFilter: 'blur(10px)',
        overflow: 'hidden',
        position: 'relative',
        transition: 'all 0.3s ease',
      }}
      bodyStyle={{ padding: 24 }}
      hoverable
    >
      {/* Top Gradient Bar */}
      <div 
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: 3,
          background: scheme.gradient,
          boxShadow: scheme.glow,
        }}
      />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ flex: 1 }}>
          {/* Title */}
          <Text 
            style={{ 
              fontSize: 12, 
              color: 'var(--text-tertiary)', 
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
              fontWeight: 600,
            }}
          >
            {title}
          </Text>

          {/* Value */}
          <div style={{ marginTop: 12, display: 'flex', alignItems: 'baseline', gap: 12 }}>
            <Text 
              style={{ 
                fontSize: 32, 
                fontWeight: 700, 
                color: 'var(--text-primary)',
                lineHeight: 1,
                letterSpacing: '-0.02em',
              }}
            >
              {value}
            </Text>
            
            {/* Trend Badge */}
            <div 
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 4,
                padding: '4px 10px',
                background: trendBg,
                borderRadius: 20,
                color: trendColor,
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {trendIcon}
            </div>
          </div>

          {/* Subtext */}
          <Text 
            style={{ 
              fontSize: 13, 
              color: 'var(--text-secondary)', 
              marginTop: 8,
              display: 'block',
            }}
          >
            {subtext}
          </Text>
        </div>

        {/* Icon */}
        <div 
          style={{ 
            width: 56, 
            height: 56, 
            background: scheme.iconBg,
            borderRadius: 14,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: `1px solid ${scheme.iconBg}`,
          }}
        >
          <Icon size={28} color={scheme.iconColor} strokeWidth={1.5} />
        </div>
      </div>

      {/* Bottom Stats Bar */}
      <div 
        style={{
          marginTop: 20,
          paddingTop: 16,
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div 
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: scheme.iconColor,
              boxShadow: `0 0 8px ${scheme.iconColor}`,
            }}
          />
          <Text style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>
            Live monitoring
          </Text>
        </div>
        <Text style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Updated just now
        </Text>
      </div>
    </Card>
  )
}
