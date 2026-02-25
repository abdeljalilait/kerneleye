export interface Server {
  id: string;
  hostname: string;
  name?: string; // mapped from hostname
  ip?: string; // mapping from ip_address
  ip_address?: string;
  user_id: string;
  agent_version: string;
  status: 'active' | 'offline' | 'warning' | 'pending' | 'rejected' | 'inactive';
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface Threat {
  source_ip: string;
  destination_port: number;
  protocol: string;
  syn_count: number;
  ack_count: number;
  failed_handshakes: number;
  unique_ports: number;
  threat_score: number;
  threat_level: 'normal' | 'suspicious' | 'malicious';
  threat_type: 'none' | 'port_scan' | 'service_abuse' | 'syn_flood' | 'failed_handshake' | 'connection_burst';
  first_seen: string;
  last_seen: string;
  country?: string;
  country_code?: string;
  city?: string;
  isp?: string;
  location?: string; // Optional if we add GeoIP later
  reason?: string;
}

export interface Alert {
  id: string;
  server_id: string;
  source_ip: string;
  threat_score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  status: 'active' | 'resolved' | 'ignored';
  auto_blocked: boolean;
  created_at: string;
}

export interface StatsOverview {
  total_servers: number;
  active_servers: number;
  total_events: number;
  total_alerts: number;
  active_threats: number;
  blocked_ips: number;
  events_last_24h: number;
  alerts_last_24h: number;
}

// WebSocket Message Types
export type EventType = 'new_threat' | 'new_alert' | 'new_traffic' | 'stats_update' | 'new_server' | 'server_updated' | 'blocked_packet';

export interface WSMessage {
  type: EventType;
  timestamp: string;
  data: any;
}
