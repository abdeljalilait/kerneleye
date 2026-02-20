import { useState, useEffect, useRef } from 'react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Card, Typography, Badge, Segmented, Space } from 'antd'
import { useWebSocket } from '../context/WebSocketContext'
import { Activity, Zap, TrendingUp } from 'lucide-react'

const { Title, Text } = Typography

interface TrafficDataPoint {
  time: string
  pps: number
  events: number
}

type TimeRange = '1m' | '5m' | '15m'

export default function TrafficChart() {
  const [data, setData] = useState<TrafficDataPoint[]>(() => {
    const initial = []
    const now = Date.now()
    for (let i = 60; i > 0; i--) {
      initial.push({
        time: new Date(now - i * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        pps: 0,
        events: 0,
      })
    }
    return initial
  })
  
  const [timeRange, setTimeRange] = useState<TimeRange>('1m')
  const [totalEvents, setTotalEvents] = useState(0)
  const [peakPps, setPeakPps] = useState(0)
  const countRef = useRef(0)
  const { lastMessage } = useWebSocket()

  // Increment count on incoming messages
  useEffect(() => {
    if (lastMessage?.type === 'new_traffic') {
      countRef.current += 1
      setTotalEvents(prev => prev + 1)
    }
  }, [lastMessage])

  // Update chart every second
  useEffect(() => {
    const interval = setInterval(() => {
      const count = countRef.current
      countRef.current = 0

      setData(prevData => {
        const now = new Date()
        const newPoint = {
          time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          pps: count,
          events: totalEvents,
        }
        const newData = [...prevData.slice(1), newPoint]
        
        // Update peak
        setPeakPps(Math.max(...newData.map(d => d.pps)))
        
        return newData
      })
    }, 1000)

    return () => clearInterval(interval)
  }, [totalEvents])

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div 
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-md)',
            padding: '12px 16px',
            boxShadow: 'var(--shadow-lg)',
          }}
        >
          <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block', marginBottom: 4 }}>
            {label}
          </Text>
          <Text strong style={{ color: 'var(--primary-400)', fontSize: 18 }}>
            {payload[0].value} events/sec
          </Text>
        </div>
      )
    }
    return null
  }

  return (
    <Card
      variant="borderless"
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        backdropFilter: 'blur(10px)',
        height: '100%',
      }}
      bodyStyle={{ padding: 24, height: '100%' }}
    >
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
            <div 
              style={{
                width: 36,
                height: 36,
                background: 'rgba(99, 102, 241, 0.15)',
                borderRadius: 10,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Activity size={18} color="#818cf8" />
            </div>
            <div>
              <Title level={5} style={{ margin: 0, color: 'var(--text-primary)', fontSize: 16 }}>
                Network Traffic
              </Title>
              <Text type="secondary" style={{ fontSize: 12 }}>
                Events per second (Real-time)
              </Text>
            </div>
          </div>
        </div>

        <Space>
          <Badge 
            status="processing" 
            text={<Text style={{ fontSize: 12, color: 'var(--success)' }}>Live</Text>}
            style={{ 
              padding: '4px 12px', 
              background: 'rgba(16, 185, 129, 0.1)',
              borderRadius: 20,
              border: '1px solid rgba(16, 185, 129, 0.2)',
            }}
          />
          <Segmented
            options={[
              { label: '1M', value: '1m' },
              { label: '5M', value: '5m' },
              { label: '15M', value: '15m' },
            ]}
            value={timeRange}
            onChange={(value) => setTimeRange(value as TimeRange)}
            size="small"
            style={{
              background: 'var(--bg-tertiary)',
            }}
          />
        </Space>
      </div>

      {/* Stats Row */}
      <div 
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 16,
          marginBottom: 24,
          padding: 16,
          background: 'var(--bg-tertiary)',
          borderRadius: 'var(--radius-md)',
        }}
      >
        <div style={{ textAlign: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 4 }}>
            <Zap size={14} color="#818cf8" />
            <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Current
            </Text>
          </div>
          <Text strong style={{ fontSize: 20, color: 'var(--text-primary)' }}>
            {data[data.length - 1]?.pps || 0}
          </Text>
          <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', marginLeft: 4 }}>pps</Text>
        </div>
        
        <div style={{ textAlign: 'center', borderLeft: '1px solid var(--border-subtle)', borderRight: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 4 }}>
            <TrendingUp size={14} color="#f59e0b" />
            <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Peak
            </Text>
          </div>
          <Text strong style={{ fontSize: 20, color: 'var(--accent-amber)' }}>
            {peakPps}
          </Text>
          <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', marginLeft: 4 }}>pps</Text>
        </div>
        
        <div style={{ textAlign: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 4 }}>
            <Activity size={14} color="#10b981" />
            <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Total
            </Text>
          </div>
          <Text strong style={{ fontSize: 20, color: 'var(--success)' }}>
            {totalEvents.toLocaleString()}
          </Text>
          <Text style={{ fontSize: 11, color: 'var(--text-tertiary)', marginLeft: 4 }}>events</Text>
        </div>
      </div>

      {/* Chart */}
      <div style={{ height: 280 }}>
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4}/>
                <stop offset="50%" stopColor="#6366f1" stopOpacity={0.1}/>
                <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorLine" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#6366f1" />
                <stop offset="50%" stopColor="#8b5cf6" />
                <stop offset="100%" stopColor="#06b6d4" />
              </linearGradient>
            </defs>
            <CartesianGrid 
              strokeDasharray="3 3" 
              stroke="rgba(255,255,255,0.05)" 
              vertical={false} 
            />
            <XAxis 
              dataKey="time" 
              stroke="rgba(255,255,255,0.2)" 
              fontSize={11} 
              tickLine={false}
              axisLine={false}
              minTickGap={30}
              tick={{ fill: 'var(--text-tertiary)' }}
            />
            <YAxis 
              stroke="rgba(255,255,255,0.2)" 
              fontSize={11} 
              tickLine={false}
              axisLine={false}
              tick={{ fill: 'var(--text-tertiary)' }}
              tickFormatter={(value) => `${value}`}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area 
              type="monotone" 
              dataKey="pps" 
              stroke="url(#colorLine)" 
              strokeWidth={3}
              fillOpacity={1} 
              fill="url(#colorPps)" 
              isAnimationActive={false}
              dot={false}
              activeDot={{ 
                r: 6, 
                stroke: '#6366f1', 
                strokeWidth: 2, 
                fill: '#0a0a0f' 
              }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}
