import { useState, useEffect, useRef } from 'react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Card, Typography, theme, Badge } from 'antd'
import { useWebSocket } from '../context/WebSocketContext'

const { Title, Text } = Typography

interface TrafficDataPoint {
  time: string
  pps: number // events per second
}

export default function TrafficChart() {
  const [data, setData] = useState<TrafficDataPoint[]>(() => {
    const initial = []
    const now = Date.now()
    for (let i = 60; i > 0; i--) {
      initial.push({
        time: new Date(now - i * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        pps: 0,
      })
    }
    return initial
  })

  // Use a ref to track counts during the current second interval
  const countRef = useRef(0)
  const { lastMessage } = useWebSocket()
  const {
      token: { colorBgContainer },
  } = theme.useToken();

  // Increment count on incoming messages
  useEffect(() => {
    if (lastMessage?.type === 'new_traffic') {
      countRef.current += 1
    }
  }, [lastMessage])

  // Update chart every second
  useEffect(() => {
    const interval = setInterval(() => {
      const count = countRef.current
      countRef.current = 0 // Reset for next second

      setData(prevData => {
        const now = new Date()
        const newPoint = {
          time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          pps: count,
        }
        return [...prevData.slice(1), newPoint]
      })
    }, 1000)

    return () => clearInterval(interval)
  }, [])

  return (
    <Card 
        title={
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                   <Title level={5} style={{ margin: 0 }}>Network Traffic</Title>
                   <Text type="secondary" style={{ fontSize: 12 }}>Events per Second (Real-time)</Text>
                </div>
                <Badge status="processing" text="Live" />
            </div>
        }
        variant="borderless"
        styles={{ body: { padding: '0 24px 24px 0' } }} // Adjust padding for chart
    >
      <div style={{ height: 256, marginTop: 16 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" vertical={false} />
            <XAxis 
              dataKey="time" 
              stroke="rgba(255,255,255,0.3)" 
              fontSize={12} 
              tickLine={false}
              axisLine={false}
              minTickGap={30}
            />
            <YAxis 
              stroke="rgba(255,255,255,0.3)" 
              fontSize={12} 
              tickLine={false}
              axisLine={false}
              tickFormatter={(value) => `${value}`}
            />
            <Tooltip 
              contentStyle={{ backgroundColor: colorBgContainer, borderColor: 'rgba(255,255,255,0.1)', color: '#f8fafc' }}
              itemStyle={{ color: '#818cf8' }}
            />
            <Area 
              type="monotone" 
              dataKey="pps" 
              stroke="#6366f1" 
              strokeWidth={2}
              fillOpacity={1} 
              fill="url(#colorPps)" 
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  )
}
