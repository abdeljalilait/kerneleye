import { useEffect, useRef } from 'react'
import { useWebSocket } from '../context/WebSocketContext'
import type { EventType } from '../types'

/**
 * Subscribe to a specific WebSocket event type.
 * The handler is called whenever a message of `eventType` arrives.
 *
 * Uses a ref internally so the handler can freely use fresh state/props
 * without needing to be listed in the effect dependency array.
 */
export function useWebSocketEvent<T = unknown>(
  eventType: EventType,
  handler: (data: T) => void,
) {
  const { lastMessage } = useWebSocket()
  const handlerRef = useRef(handler)
  handlerRef.current = handler

  useEffect(() => {
    if (lastMessage?.type === eventType) {
      handlerRef.current(lastMessage.data as T)
    }
  }, [lastMessage, eventType])
}
