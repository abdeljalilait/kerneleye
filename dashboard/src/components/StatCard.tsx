import { Card, Statistic, theme as antTheme } from 'antd'
import { ArrowUpOutlined, ArrowDownOutlined, MinusOutlined } from '@ant-design/icons'
import { LucideIcon } from 'lucide-react'

interface StatCardProps {
  title: string
  value: string
  subtext: string
  icon: LucideIcon
  trend?: 'up' | 'down' | 'neutral'
  color?: 'primary' | 'success' | 'warning' | 'error' | 'cyan'
}

const colorMap: Record<string, { bg: string; color: string; border: string }> = {
  primary:   { bg: 'rgba(99,102,241,0.12)',  color: '#818cf8', border: 'rgba(99,102,241,0.2)' },
  success:   { bg: 'rgba(16,185,129,0.12)',  color: '#34d399', border: 'rgba(16,185,129,0.2)' },
  warning:   { bg: 'rgba(245,158,11,0.12)',  color: '#fbbf24', border: 'rgba(245,158,11,0.2)' },
  error:     { bg: 'rgba(239,68,68,0.12)',   color: '#f87171', border: 'rgba(239,68,68,0.2)' },
  cyan:      { bg: 'rgba(6,182,212,0.12)',   color: '#22d3ee', border: 'rgba(6,182,212,0.2)' },
}

export default function StatCard({ title, value, subtext, icon: Icon, trend, color = 'primary' }: StatCardProps) {
  const { token } = antTheme.useToken()
  const scheme = colorMap[color]

  const trendConfig = trend === 'up'
    ? { icon: <ArrowUpOutlined />, color: token.colorSuccess, valueStyle: { color: token.colorSuccess } }
    : trend === 'down'
      ? { icon: <ArrowDownOutlined />, color: token.colorError, valueStyle: { color: token.colorError } }
      : { icon: <MinusOutlined />, color: token.colorTextTertiary, valueStyle: {} }

  return (
    <Card
      hoverable
      styles={{
        body: { padding: token.paddingLG },
      }}
    >
      {/* Colored accent bar at top */}
      <div
        style={{
          position: 'absolute',
          top: 0, left: 0, right: 0,
          height: 3,
          background: `linear-gradient(135deg, ${scheme.color}, ${scheme.color}cc)`,
          borderTopLeftRadius: token.borderRadiusLG,
          borderTopRightRadius: token.borderRadiusLG,
        }}
      />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <Statistic
          title={title}
          value={value}
          prefix={trendConfig.icon}
          valueStyle={{ fontWeight: 700, fontSize: 32, letterSpacing: '-0.02em', ...trendConfig.valueStyle }}
          styles={{
            content: { marginTop: 8 },
          }}
        />
        {/* Icon box */}
        <div
          style={{
            width: 52, height: 52,
            background: scheme.bg,
            borderRadius: token.borderRadius,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: `1px solid ${scheme.border}`,
            flexShrink: 0,
            marginTop: 4,
          }}
        >
          <Icon size={26} color={scheme.color} strokeWidth={1.5} />
        </div>
      </div>

      {/* Subtext below */}
      <div style={{ marginTop: token.marginSM, color: token.colorTextSecondary, fontSize: token.fontSize }}>
        {subtext}
      </div>
    </Card>
  )
}
