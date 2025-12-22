import { Card, Statistic } from 'antd'
import { LucideIcon } from 'lucide-react'
import { ArrowUpOutlined, ArrowDownOutlined, MinusOutlined } from '@ant-design/icons'

interface StatCardProps {
  title: string
  value: string
  subtext: string
  icon: LucideIcon
  trend?: 'up' | 'down' | 'neutral'
}

export default function StatCard({ title, value, subtext, icon: Icon, trend }: StatCardProps) {
  let trendIcon = <MinusOutlined />
  let trendColor = '#8c8c8c' // neutral

  if (trend === 'up') {
      trendIcon = <ArrowUpOutlined />
      trendColor = '#cf1322' // typically red for threats/load, but maybe green? 
      // User context: "Active Threats" -> up is bad. "Monitored Servers" -> up is good.
      // Re-reading logic: "Active Threats > 0 ? up". "Monitored Servers > 0 ? up".
      // Let's stick to neutral colors or context specific.
      // For now, let's just make 'up' green and 'down' red, except for threats where it might be inverse?
      // Simpler: Just use generic colors.
      trendColor = '#3f8600'
  } else if (trend === 'down') {
      trendIcon = <ArrowDownOutlined />
      trendColor = '#cf1322'
  }

  // Override for threats/alerts if logic implies badness?
  // Previous code: trend === 'up' ? 'text-green-400'
  // So 'up' was green.

  const subtextStyle = { color: 'rgba(255,255,255,0.45)', fontSize: 12, marginTop: 4 }

  return (
    <Card variant="borderless" hoverable>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <Statistic 
                title={title} 
                value={value} 
                valueStyle={{ color: trendColor }}
                prefix={trendIcon}
            />
            <div style={{ padding: 8, background: 'rgba(255,255,255,0.04)', borderRadius: 6 }}>
                <Icon size={20} style={{ opacity: 0.7 }} />
            </div>
        </div>
        <div style={subtextStyle}>{subtext}</div>
    </Card>
  )
}
