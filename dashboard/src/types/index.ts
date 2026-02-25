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
  is_blocked?: boolean;
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

// Traffic Event from server traffic endpoint
export interface TrafficEvent {
  id: string;
  source_ip: string;
  destination_port: number;
  protocol: string;
  syn_count: number;
  ack_count: number;
  failed_handshakes: number;
  unique_ports: number;
  bytes_in: number;
  bytes_out: number;
  threat_score: number;
  threat_level: string;
  threat_type?: string;
  country: string | null;
  country_code?: string | null;
  city: string | null;
  isp: string | null;
  hit_count: number;
  first_seen: string;
  last_seen: string;
  created_at: string;
  direction?: string;
  destination_ip?: string | null;
}

// Pagination metadata
export interface Pagination {
  page: number;
  page_size: number;
  total_count: number;
  total_pages: number;
}

// Paginated response wrapper
export interface PaginatedResponse<T> {
  data: T[];
  pagination: Pagination;
}

// Port Traffic (aggregated by port/protocol)
export interface PortSourceIP {
  source_ip: string;
  destination_port?: number;
  destination_ip?: string | null;
  bytes_in: number;
  bytes_out: number;
  syn_count: number;
  ack_count: number;
  hit_count: number;
  threat_score: number;
  threat_level: string;
  country?: string;
  city?: string;
  isp?: string;
  last_seen: string;
  direction?: string;
}

export interface PortTraffic {
  port: number;
  protocol: string;
  unique_ips: number;
  total_bytes_in: number;
  total_bytes_out: number;
  total_hits: number;
  total_syn: number;
  total_ack: number;
  max_threat_score: number;
  max_threat_level: string;
  last_seen: string;
  sources: PortSourceIP[];
}

// Protocol Traffic (aggregated by protocol only)
export interface ProtocolTraffic {
  protocol: string;
  unique_ips: number;
  unique_ports: number;
  total_bytes_in: number;
  total_bytes_out: number;
  total_hits: number;
  total_syn: number;
  total_ack: number;
  max_threat_score: number;
  max_threat_level: string;
  last_seen: string;
  sources: PortSourceIP[];
}

// WebSocket Message Types
export type EventType = 'new_threat' | 'new_alert' | 'new_traffic' | 'stats_update' | 'new_server' | 'server_updated' | 'blocked_packet' | 'new_block' | 'unblock_ip' | 'threat_detected';

export interface WSMessage {
  type: EventType;
  timestamp: string;
  data: any;
}
