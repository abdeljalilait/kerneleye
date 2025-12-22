import React, { createContext, useContext, useEffect, useRef, useState } from 'react'
import { WSMessage } from '../types'

interface WebSocketContextType {
  isConnected: boolean
  lastMessage: WSMessage | null
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined)

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<number | undefined>(undefined)

  const connect = () => {
    // If already connected or connecting, don't start another one
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return
    }

    const token = localStorage.getItem('kerneleye_token')
    let wsUrl: string;

    if (import.meta.env.VITE_API_URL && import.meta.env.VITE_API_URL.startsWith('http')) {
      const url = new URL(import.meta.env.VITE_API_URL);
      const wsProtocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
      wsUrl = `${wsProtocol}//${url.host}/api/v1/ws`;
    } else {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      wsUrl = `${protocol}//${window.location.host}/api/v1/ws`;
    }

    if (token) {
        wsUrl += `?token=${token}`
    }

    console.log(`Connecting to WebSocket: ${wsUrl.replace(token || '', '***')}`)
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      console.log('✅ WebSocket Connected')
      setIsConnected(true)
    }

    ws.onclose = (event) => {
      console.log(`❌ WebSocket Disconnected (Code: ${event.code}, Reason: ${event.reason || 'none'})`)
      setIsConnected(false)
      wsRef.current = null
      
      // Only reconnect if not closed intentionally
      if (event.code !== 1000) {
        reconnectTimeoutRef.current = window.setTimeout(connect, 3000)
      }
    }

    ws.onerror = (err) => {
      console.error('⚠️ WebSocket Error:', err)
      // Note: onclose will handle reconnect
    }

    ws.onmessage = (event) => {
      try {
        const message: WSMessage = JSON.parse(event.data)
        setLastMessage(message)
      } catch (e) {
        console.error('Failed to parse WS message:', e)
      }
    }
  }

  useEffect(() => {
    connect()
    return () => {
      if (wsRef.current) {
        // Use code 1000 for normal closure to prevent auto-reconnect
        if (wsRef.current.readyState === WebSocket.OPEN) {
          wsRef.current.close(1000, "Component unmounted")
        } else if (wsRef.current.readyState === WebSocket.CONNECTING) {
          // If still connecting, we just null it out or close it.
          // Standard doesn't allow code/reason for connecting state in some browsers but we try.
          wsRef.current.onclose = null // Prevent the onclose log/reconnect
          wsRef.current.close()
        }
        wsRef.current = null
      }
      clearTimeout(reconnectTimeoutRef.current)
    }
  }, [])

  return (
    <WebSocketContext.Provider value={{ isConnected, lastMessage }}>
      {children}
    </WebSocketContext.Provider>
  )
}

// Custom hook moved to end to avoid Fast Refresh issues if it's the only export besides provider
export const useWebSocket = () => {
  const context = useContext(WebSocketContext)
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider')
  }
  return context
}
