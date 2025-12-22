import { Table, Tag, Input, Button, Typography, Card } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Globe, Search } from 'lucide-react'
import { Threat } from '../types'

const { Text } = Typography

interface ThreatsListProps {
  threats: Threat[]
}

export default function ThreatsList({ threats }: ThreatsListProps) {
  const getRiskTag = (score: number) => {
    if (score >= 40) {
      return <Tag color="error">{score} - Malicious</Tag>
    } else if (score >= 20) {
      return <Tag color="warning">{score} - Suspicious</Tag>
    }
    return <Tag color="success">{score} - Clean</Tag>
  }

  const columns: ColumnsType<Threat> = [
    {
      title: 'Source IP',
      dataIndex: 'source_ip',
      key: 'source_ip',
      render: (ip, record) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
           <Globe size={14} style={{ opacity: 0.5 }} />
           <Text code>{ip}</Text>
           {record.location && <Tag>{record.location}</Tag>}
        </div>
      )
    },
    {
      title: 'Reason',
      dataIndex: 'reason',
      key: 'reason',
      render: (text) => <Text ellipsis style={{ maxWidth: 300 }}>{text || 'Detected by heuristics'}</Text>
    },
    {
      title: 'Risk Score',
      dataIndex: 'threat_score',
      key: 'score',
      render: (score) => getRiskTag(score)
    },
    {
      title: 'Action',
      key: 'action',
      render: () => (
         <div style={{ display: 'flex', gap: 8 }}>
            <Button size="small" type="link">Analyze</Button>
            <Button size="small" type="link" danger>Block</Button>
         </div>
      )
    }
  ]

  return (
    <Card 
        title="Top Detected Threats" 
        extra={
            <Input 
                placeholder="Search IP..." 
                prefix={<Search size={14} style={{ opacity: 0.5 }} />} 
                style={{ width: 200, background: 'rgba(255,255,255,0.05)' }}
            />
        }
        variant="borderless"
        styles={{ body: { padding: 0 } }}
    >
      <Table 
        columns={columns} 
        dataSource={threats} 
        rowKey={(record) => `${record.source_ip}-${record.last_seen || Math.random()}`}
        pagination={{ pageSize: 5 }}
        locale={{ emptyText: 'No threats detected' }}
      />
    </Card>
  )
}
