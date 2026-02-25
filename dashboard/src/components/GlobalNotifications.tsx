import { useEffect } from 'react'
import { notification } from 'antd'
import { useWebSocket } from '../context/WebSocketContext'
import { Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'

export default function GlobalNotifications() {
  const { lastMessage } = useWebSocket()

  useEffect(() => {
    if (!lastMessage) return

    const { type, data } = lastMessage

    switch (type) {
      case 'new_block':
        notification.info({
          message: (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={18} color="#ef4444" />
              <span>IP Blocked</span>
            </div>
          ),
          description: (
            <div>
              <div style={{ fontFamily: 'monospace', fontWeight: 600 }}>
                {data.ip_address}
              </div>
              <div style={{ fontSize: 12, color: 'rgba(0,0,0,0.6)', marginTop: 4 }}>
                Score: {data.threat_score} • Duration: {Math.round(data.duration / 60)}m
              </div>
            </div>
          ),
          placement: 'topRight',
          duration: 5,
          style: { background: '#fef2f2', border: '1px solid #fecaca' },
        })
        break

      case 'new_threat':
        notification.warning({
          message: (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={18} color="#f59e0b" />
              <span>Threat Detected</span>
            </div>
          ),
          description: (
            <div>
              <div style={{ fontFamily: 'monospace', fontWeight: 600 }}>
                {data.source_ip}
              </div>
              <div style={{ fontSize: 12, color: 'rgba(0,0,0,0.6)', marginTop: 4 }}>
                Score: {data.threat_score} • {data.reason}
              </div>
            </div>
          ),
          placement: 'topRight',
          duration: 5,
          style: { background: '#fffbeb', border: '1px solid #fed7aa' },
        })
        break

      case 'unblock_ip':
        notification.success({
          message: (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <CheckCircle size={18} color="#10b981" />
              <span>IP Unblocked</span>
            </div>
          ),
          description: (
            <div style={{ fontFamily: 'monospace', fontWeight: 600 }}>
              {data.ip_address}
            </div>
          ),
          placement: 'topRight',
          duration: 5,
          style: { background: '#ecfdf5', border: '1px solid #a7f3d0' },
        })
        break

      case 'blocked_packet':
        notification.info({
          message: (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <XCircle size={18} color="#6366f1" />
              <span>Blocked Packet</span>
            </div>
          ),
          description: (
            <div>
              <div style={{ fontFamily: 'monospace', fontWeight: 600 }}>
                {data.source_ip}
              </div>
              <div style={{ fontSize: 12, color: 'rgba(0,0,0,0.6)', marginTop: 4 }}>
                Port: {data.port} • {data.protocol}
              </div>
            </div>
          ),
          placement: 'topRight',
          duration: 3,
          style: { background: '#eef2ff', border: '1px solid #c7d2fe' },
        })
        break
    }
  }, [lastMessage])

  return null
}
