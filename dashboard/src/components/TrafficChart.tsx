import { useState, useEffect, useRef } from 'react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Card, Typography, Segmented, Space, Statistic, Row, Col, theme } from 'antd'
import { useWebSocket } from '../context/WebSocketContext'
import { Activity } from 'lucide-react'

const { Text, Title } = Typography

interface TrafficDataPoint {
  time: string
  pps: number
  events: number
}

type TimeRange = '1m' | '5m' | '15m'

export default function TrafficChart() {
  const [data, setData] = useState<TrafficDataPoint[]>(() => {
    const initial: TrafficDataPoint[] = []
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
  const totalEventsRef = useRef(0)
  const { lastMessage } = useWebSocket()
  const { token } = theme.useToken()

  useEffect(() => {
    if (lastMessage?.type === 'new_traffic') {
      countRef.current += 1
      totalEventsRef.current += 1
      setTotalEvents(totalEventsRef.current)
    }
  }, [lastMessage])

  useEffect(() => {
    const interval = setInterval(() => {
      const count = countRef.current
      countRef.current = 0

      setData(prevData => {
        const now = new Date()
        const newPoint = {
          time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          pps: count,
          events: totalEventsRef.current,
        }
        const newData = [...prevData.slice(1), newPoint]
        setPeakPps(Math.max(...newData.map(d => d.pps)))
        return newData
      })
    }, 1000)

    return () => clearInterval(interval)
  }, [])

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div
          style={{
            background: token.colorBgElevated,
            border: `1px solid ${token.colorBorder}`,
            borderRadius: token.borderRadius,
            padding: '12px 16px',
            boxShadow: token.boxShadowSecondary,
          }}
        >
          <Text style={{ color: token.colorTextTertiary, fontSize: 12, display: 'block', marginBottom: 4 }}>
            {label}
          </Text>
          <Text strong style={{ color: token.colorPrimary, fontSize: 18 }}>
            {payload[0].value} events/sec
          </Text>
        </div>
      )
    }
    return null
  }

  const currentPps = data[data.length - 1]?.pps || 0

  return (
    <Card
      styles={{ body: { padding: token.paddingLG } }}
      title={
        <Space size={12}>
          <div
            style={{
              width: 36, height: 36,
              background: token.colorPrimaryBg,
              borderRadius: token.borderRadius,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Activity size={18} color={token.colorPrimary} />
          </div>
          <div>
            <Title level={5} style={{ margin: 0, fontSize: 16 }}>Network Traffic</Title>
            <Text type="secondary" style={{ fontSize: 12 }}>Events per second (Real-time)</Text>
          </div>
        </Space>
      }
      extra={
        <Space>
          <Text type="secondary" style={{ fontSize: 12 }}>
            ● Live
          </Text>
          <Segmented
            size="small"
            options={[
              { label: '1M', value: '1m' },
              { label: '5M', value: '5m' },
              { label: '15M', value: '15m' },
            ]}
            value={timeRange}
            onChange={(value) => setTimeRange(value as TimeRange)}
          />
        </Space>
      }
    >
      {/* Stats row */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={8}>
          <Statistic title="Current" value={currentPps} suffix="pps" valueStyle={{ fontSize: 24 }} />
        </Col>
        <Col span={8}>
          <Statistic title="Peak" value={peakPps} suffix="pps" valueStyle={{ fontSize: 24, color: token.colorWarning }} />
        </Col>
        <Col span={8}>
          <Statistic title="Total" value={totalEvents} suffix="events" valueStyle={{ fontSize: 24, color: token.colorSuccess }} />
        </Col>
      </Row>

      {/* Chart */}
      <div style={{ height: 280 }}>
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={token.colorPrimary} stopOpacity={0.4} />
                <stop offset="50%" stopColor={token.colorPrimary} stopOpacity={0.1} />
                <stop offset="95%" stopColor={token.colorPrimary} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorLine" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor={token.colorPrimary} />
                <stop offset="50%" stopColor="#8b5cf6" />
                <stop offset="100%" stopColor="#06b6d4" />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={token.colorBorderSecondary} vertical={false} />
            <XAxis
              dataKey="time"
              stroke={token.colorTextQuaternary}
              fontSize={11}
              tickLine={false}
              axisLine={false}
              minTickGap={30}
            />
            <YAxis
              stroke={token.colorTextQuaternary}
              fontSize={11}
              tickLine={false}
              axisLine={false}
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
              activeDot={{ r: 6, stroke: token.colorPrimary, strokeWidth: 2, fill: token.colorBgBase }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}
