package api

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

type EventType string

const (
	EventNewThreat  EventType = "new_threat"
	EventNewAlert   EventType = "new_alert"
	EventNewTraffic EventType = "new_traffic"
	EventNewServer  EventType = "new_server"
	EventStats      EventType = "stats_update"
)

type WSMessage struct {
	Type      EventType   `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

type Client struct {
	Conn   *websocket.Conn
	UserID string
}

type BroadcastMessage struct {
	UserID  string
	Message WSMessage
}

type Hub struct {
	// Registered clients map[userID]map[conn]bool
	clients map[string]map[*websocket.Conn]bool

	// Inbound messages from the clients.
	broadcast chan BroadcastMessage

	// Register requests from the clients.
	register chan Client

	// Unregister requests from clients.
	unregister chan Client

	// Lock for map access
	mu sync.Mutex
}

func NewHub() *Hub {
	return &Hub{
		broadcast:  make(chan BroadcastMessage),
		register:   make(chan Client),
		unregister: make(chan Client),
		clients:    make(map[string]map[*websocket.Conn]bool),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			if _, ok := h.clients[client.UserID]; !ok {
				h.clients[client.UserID] = make(map[*websocket.Conn]bool)
			}
			h.clients[client.UserID][client.Conn] = true
			h.mu.Unlock()
			log.Printf("Client connected to WebSocket (User: %s)", client.UserID)

		case client := <-h.unregister:
			h.mu.Lock()
			if userClients, ok := h.clients[client.UserID]; ok {
				if _, ok := userClients[client.Conn]; ok {
					delete(userClients, client.Conn)
					client.Conn.Close()
				}
				if len(userClients) == 0 {
					delete(h.clients, client.UserID)
				}
			}
			h.mu.Unlock()
			log.Printf("Client disconnected from WebSocket (User: %s)", client.UserID)

		case broadcast := <-h.broadcast:
			msgBytes, err := json.Marshal(broadcast.Message)
			if err != nil {
				log.Printf("Failed to marshal WS message: %v", err)
				continue
			}

			h.mu.Lock()
			if userClients, ok := h.clients[broadcast.UserID]; ok {
				for client := range userClients {
					if err := client.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
						log.Printf("Failed to write to client: %v", err)
						client.Close()
						delete(userClients, client)
					}
				}
				// Clean up if empty
				if len(userClients) == 0 {
					delete(h.clients, broadcast.UserID)
				}
			}
			h.mu.Unlock()
		}
	}
}

func (h *Hub) Broadcast(userID string, eventType EventType, data interface{}) {
	h.broadcast <- BroadcastMessage{
		UserID: userID,
		Message: WSMessage{
			Type:      eventType,
			Timestamp: time.Now(),
			Data:      data,
		},
	}
}

// UpgradeMiddleware ensures the request is a websocket upgrade
func UpgradeMiddleware(c *fiber.Ctx) error {
	if websocket.IsWebSocketUpgrade(c) {
		c.Locals("allowed", true)
		return c.Next()
	}
	return fiber.ErrUpgradeRequired
}

// WebSocketHandler returns the handler for websocket connections
func WebSocketHandler(hub *Hub) func(c *fiber.Ctx) error {
	return websocket.New(func(c *websocket.Conn) {
		// Get user ID from Locals (set by AuthMiddleware)
		userID := c.Locals("user_id").(string)

		client := Client{
			Conn:   c,
			UserID: userID,
		}

		// Register the client
		hub.register <- client

		// Cleanup on exit
		defer func() {
			hub.unregister <- client
		}()

		// Infinite loop to keep connection alive and read control messages
		for {
			_, _, err := c.ReadMessage()
			if err != nil {
				// Error usually means disconnect
				break
			}
		}
	})
}
