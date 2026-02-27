import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { serversAPI, threatsAPI, alertsAPI, statsAPI, authAPI, subscriptionAPI, analyticsAPI, agentConfigAPI, blocksAPI, whitelistAPI } from '../api/client';
import type { Server, Threat, Alert, StatsOverview, TrafficEvent, PaginatedResponse, PortTraffic, ProtocolTraffic, PortSourceIP } from '../types';

export const useServers = () => {
  return useQuery({
    queryKey: ['servers'],
    queryFn: async () => {
      const { data } = await serversAPI.list();
      return data as Server[];
    },
  });
};

export const useThreats = () => {
  return useQuery({
    queryKey: ['threats'],
    queryFn: async () => {
      const { data } = await threatsAPI.list();
      return data as Threat[];
    },
  });
};

export const useBlocks = (params?: { page?: number; page_size?: number; server?: string; status?: string }) => {
  return useQuery({
    queryKey: ['blocks', params],
    queryFn: async () => {
      const { data } = await blocksAPI.list(params);
      return data;
    },
  });
};

export const useBlockStats = () => {
  return useQuery({
    queryKey: ['block-stats'],
    queryFn: async () => {
      const { data } = await blocksAPI.stats();
      return data;
    },
  });
};

export const useUnblockIP = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ ip, reason }: { ip: string; reason?: string }) => blocksAPI.unblock(ip, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['blocks'] });
    },
  });
};

export const useWhitelist = () => {
  return useQuery({
    queryKey: ['whitelist'],
    queryFn: async () => {
      const { data } = await whitelistAPI.list();
      return data || [];
    },
  });
};

export const useAddToWhitelist = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ ip, reason }: { ip: string; reason?: string }) => whitelistAPI.add(ip, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['whitelist'] });
    },
  });
};

export const useRemoveFromWhitelist = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (ip: string) => whitelistAPI.remove(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['whitelist'] });
    },
  });
};

export const useAlerts = () => {
  return useQuery({
    queryKey: ['alerts'],
    queryFn: async () => {
      const { data } = await alertsAPI.list();
      return data as Alert[];
    },
  });
};

export const useStats = () => {
  return useQuery({
    queryKey: ['stats'],
    queryFn: async () => {
      const { data } = await statsAPI.overview();
      return data as StatsOverview;
    },
  });
};

// Server detail hooks
export const useServer = (id: string | undefined) => {
  return useQuery({
    queryKey: ['server', id],
    queryFn: async () => {
      const { data } = await serversAPI.get(id!);
      return data as {
        id: string;
        hostname: string;
        status: string;
        ip_address: string | null;
        agent_version: string | null;
        cpu_usage: number;
        memory_usage: number;
        uptime_seconds: number;
        last_seen: string;
      };
    },
    enabled: !!id,
  });
};

export const useServerStats = (id: string | undefined) => {
  return useQuery({
    queryKey: ['server', id, 'stats'],
    queryFn: async () => {
      const { data } = await serversAPI.getStats(id!);
      return data as {
        total_events: number;
        events_last_24h: number;
        threat_events: number;
        total_bytes_in: number;
        total_bytes_out: number;
      };
    },
    enabled: !!id,
  });
};

export const useServerTraffic = (id: string | undefined, params?: { page?: number; page_size?: number; search?: string; threat_level?: string; sort_by?: string; from?: string; to?: string }) => {
  return useQuery({
    queryKey: ['server', id, 'traffic', params],
    queryFn: async () => {
      const { data } = await serversAPI.getTraffic(id!, params);
      return data as PaginatedResponse<TrafficEvent>;
    },
    enabled: !!id,
  });
};

export const useServerPortTraffic = (id: string | undefined, params?: { page?: number; page_size?: number; search?: string; threat_level?: string; sort_by?: string; from?: string; to?: string }) => {
  return useQuery({
    queryKey: ['server', id, 'port-traffic', params],
    queryFn: async () => {
      const { data } = await serversAPI.getPortTraffic(id!, params);
      return data as PaginatedResponse<PortTraffic>;
    },
    enabled: !!id,
  });
};

export const useServerProtocolTraffic = (id: string | undefined, params?: { page?: number; page_size?: number; search?: string; threat_level?: string; sort_by?: string; from?: string; to?: string }) => {
  return useQuery({
    queryKey: ['server', id, 'protocol-traffic', params],
    queryFn: async () => {
      const { data } = await serversAPI.getProtocolTraffic(id!, params);
      return data as PaginatedResponse<ProtocolTraffic>;
    },
    enabled: !!id,
  });
};

export const useServerPortSources = (id: string | undefined, port: number | undefined, protocol: string | undefined, params?: { page?: number; page_size?: number; search?: string; sort_by?: string; sort_order?: string }) => {
  return useQuery({
    queryKey: ['server', id, 'port-sources', port, protocol, params],
    queryFn: async () => {
      const { data } = await serversAPI.getPortSources(id!, port!, protocol!, params);
      return data as PaginatedResponse<PortSourceIP>;
    },
    enabled: !!id && !!port && !!protocol,
  });
};

// ============ MUTATIONS ============

// Auth mutations & queries
export const useProfile = () => {
  return useQuery({
    queryKey: ['profile'],
    queryFn: async () => {
      const { data } = await authAPI.getMe();
      return data as { id: string; email: string; plan: string };
    },
  });
};

export interface OAuthProvider {
  id: string;
  name: string;
  icon: string;
}

export const useOAuthProviders = () => {
  return useQuery({
    queryKey: ['auth', 'providers'],
    queryFn: async () => {
      const { data } = await authAPI.getProviders();
      return data.providers as OAuthProvider[];
    },
    staleTime: 5 * 60 * 1000, // 5 minutes - providers don't change often
  });
};

export const useLogin = () => {
  return useMutation({
    mutationFn: async ({ email, password }: { email: string; password: string }) => {
      const { data } = await authAPI.login(email, password);
      return data as { token: string };
    },
  });
};

export const useRegister = () => {
  return useMutation({
    mutationFn: async ({ email, password }: { email: string; password: string }) => {
      const { data } = await authAPI.register(email, password);
      return data as { token: string };
    },
  });
};

// Agent configuration hooks
export const useDeploymentModes = () => {
  return useQuery({
    queryKey: ['deployment-modes'],
    queryFn: async () => {
      const { data } = await agentConfigAPI.getDeploymentModes();
      return data as Array<{
        key: string;
        name: string;
        description: string;
        requirements: string;
        performance: string;
        compatibility: string;
      }>;
    },
  });
};

export const useAgentFeatures = () => {
  return useQuery({
    queryKey: ['agent-features'],
    queryFn: async () => {
      const { data } = await agentConfigAPI.getFeatures();
      return data as Array<{
        key: string;
        name: string;
        description: string;
        flag: string;
        env_var: string;
        default_value: boolean;
        available_in: string[];
        details: string;
        example: string;
        benefits: string[];
        risks?: string[];
      }>;
    },
  });
};

export const useServerConfig = (id: string | undefined) => {
  return useQuery({
    queryKey: ['server', id, 'config'],
    queryFn: async () => {
      const { data } = await serversAPI.getConfig(id!);
      return data as {
        mode: string;
        features: Record<string, boolean>;
        threshold: number;
        duration: string;
      };
    },
    enabled: !!id,
  });
};

// Server mutations
export const useGenerateApiKey = () => {
  return useMutation({
    mutationFn: async () => {
      const { data } = await serversAPI.generateApiKey();
      return data as { api_key: string };
    },
  });
};

export const useCreateServerWithConfig = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { server_name: string; config: any }) => {
      const { data: response } = await serversAPI.create(data);
      return response as {
        api_key: string;
        server_id: string;
        commands: Record<string, string>;
        environment: Record<string, string>;
      };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] });
    },
  });
};

export const useUpdateServerConfig = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, config }: { id: string; config: any }) => {
      const { data } = await serversAPI.updateConfig(id, config);
      return data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['server', variables.id, 'config'] });
    },
  });
};

export const useCreateServer = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (_hostname: string) => {
      const { data } = await serversAPI.generateApiKey();
      return data as { api_key: string; install_command: string };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] });
    },
  });
};

export const useUpdateServerStatus = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const { data } = await serversAPI.updateStatus(id, status);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] });
    },
  });
};

export const useDeleteServer = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await serversAPI.delete(id);
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['threats'] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
};

// ============ SUBSCRIPTION HOOKS ============

export interface Plan {
  id: string;
  name: string;
  display_name: string;
  description: string;
  price_cents: number;
  currency: string;
  billing_interval: string;
  max_servers: number;
  data_retention_days: number;
  features: Record<string, any>;
  is_default: boolean;
  polar_price_id?: string;
}

export interface SubscriptionStatus {
  plan: string;
  plan_display_name: string;
  status: string;
  max_servers: number;
  current_servers: number;
  data_retention_days: number;
  features: Record<string, any>;
  current_period_start?: string;
  current_period_end?: string;
  cancel_at_period_end: boolean;
  trial_ends_at?: string;
  is_trialing: boolean;
  has_used_trial: boolean;
}

export const useSubscriptionPlans = () => {
  return useQuery({
    queryKey: ['subscription', 'plans'],
    queryFn: async () => {
      const { data } = await subscriptionAPI.getPlans();
      return data as Plan[];
    },
  });
};

export const useSubscriptionStatus = () => {
  return useQuery({
    queryKey: ['subscription', 'status'],
    queryFn: async () => {
      const { data } = await subscriptionAPI.getStatus();
      return data as SubscriptionStatus;
    },
  });
};

export interface CheckoutResponse {
  checkout_url: string;
  session_id?: string;
  customer_email: string;
  metadata: any;
  embedded?: boolean;
}

export const useCreateCheckout = () => {
  return useMutation({
    mutationFn: async ({ planName, embedOrigin }: { planName: string; embedOrigin?: string }) => {
      const { data } = await subscriptionAPI.createCheckout(planName, embedOrigin);
      return data as CheckoutResponse;
    },
  });
};

export const useCreateCustomerPortal = () => {
  return useMutation({
    mutationFn: async () => {
      const { data } = await subscriptionAPI.createCustomerPortal();
      return data as { portal_url: string };
    },
  });
};

// ============================================
// SYSTEM STATUS HOOK
// ============================================

export interface SystemStatus {
  status: 'healthy' | 'warning' | 'error';
  message: string;
  lastHeartbeat: string | null;
  lastHeartbeatAgo: string;
  activeServers: number;
  totalServers: number;
}

export const useSystemStatus = () => {
  return useQuery({
    queryKey: ['system-status'],
    queryFn: async () => {
      const { data } = await serversAPI.list();
      const servers = data as Server[];
      
      if (!servers || servers.length === 0) {
        return {
          status: 'error',
          message: 'No servers configured',
          lastHeartbeat: null,
          lastHeartbeatAgo: 'Never',
          activeServers: 0,
          totalServers: 0,
        } as SystemStatus;
      }

      // Find the most recent heartbeat across all servers
      const now = new Date().getTime();
      const heartbeats = servers
        .map(s => s.last_seen ? new Date(s.last_seen).getTime() : 0)
        .filter(t => t > 0);
      
      const lastHeartbeat = heartbeats.length > 0 ? Math.max(...heartbeats) : 0;
      const lastHeartbeatAgo = lastHeartbeat > 0 ? now - lastHeartbeat : Infinity;
      
      // Count servers active in last 5 minutes
      const fiveMinutes = 5 * 60 * 1000;
      const activeServers = heartbeats.filter(t => now - t < fiveMinutes).length;
      
      // Determine status
      let status: 'healthy' | 'warning' | 'error' = 'healthy';
      let message = 'All systems operational';
      
      if (lastHeartbeat === 0 || lastHeartbeatAgo > 10 * 60 * 1000) {
        // No heartbeat in 10 minutes
        status = 'error';
        message = activeServers > 0 
          ? `${servers.length - activeServers} server(s) not reporting`
          : 'No agent heartbeats received';
      } else if (lastHeartbeatAgo > 5 * 60 * 1000) {
        // Last heartbeat between 5-10 minutes
        status = 'warning';
        message = `Last heartbeat ${Math.floor(lastHeartbeatAgo / 60000)} min ago`;
      } else if (activeServers < servers.length) {
        // Some servers not active
        status = 'warning';
        message = `${activeServers}/${servers.length} servers active`;
      }

      return {
        status,
        message,
        lastHeartbeat: lastHeartbeat > 0 ? new Date(lastHeartbeat).toISOString() : null,
        lastHeartbeatAgo: lastHeartbeat > 0 
          ? formatDuration(lastHeartbeatAgo)
          : 'Never',
        activeServers,
        totalServers: servers.length,
      } as SystemStatus;
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
};

// Helper to format duration
function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  
  if (hours > 0) return `${hours}h ${minutes % 60}m ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return `${seconds}s ago`;
}

// ============================================
// ANALYTICS HOOKS (Reports & Visualizer)
// ============================================

// Reports hooks
export const useDailyAttackStats = (startDate?: string, endDate?: string) => {
  return useQuery({
    queryKey: ['analytics', 'daily-attacks', startDate, endDate],
    queryFn: async () => {
      const { data } = await analyticsAPI.getDailyAttacks(startDate, endDate);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useDailyBlockStats = (startDate?: string, endDate?: string) => {
  return useQuery({
    queryKey: ['analytics', 'daily-blocks', startDate, endDate],
    queryFn: async () => {
      const { data } = await analyticsAPI.getDailyBlocks(startDate, endDate);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useAttackTypeBreakdown = (startDate?: string, endDate?: string) => {
  return useQuery({
    queryKey: ['analytics', 'attack-types', startDate, endDate],
    queryFn: async () => {
      const { data } = await analyticsAPI.getAttackTypes(startDate, endDate);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useTopSourceCountries = (startDate?: string, endDate?: string, limit?: number) => {
  return useQuery({
    queryKey: ['analytics', 'top-countries', startDate, endDate, limit],
    queryFn: async () => {
      const { data } = await analyticsAPI.getTopCountries(startDate, endDate, limit);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useHourlyAttackDistribution = (startDate?: string, endDate?: string) => {
  return useQuery({
    queryKey: ['analytics', 'hourly-distribution', startDate, endDate],
    queryFn: async () => {
      const { data } = await analyticsAPI.getHourlyDistribution(startDate, endDate);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useThreatTrends = (startDate?: string, endDate?: string) => {
  return useQuery({
    queryKey: ['analytics', 'threat-trends', startDate, endDate],
    queryFn: async () => {
      const { data } = await analyticsAPI.getThreatTrends(startDate, endDate);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

// Visualizer hooks
export const useTopSourceIPs = (startDate?: string, endDate?: string, limit?: number) => {
  return useQuery({
    queryKey: ['analytics', 'top-source-ips', startDate, endDate, limit],
    queryFn: async () => {
      const { data } = await analyticsAPI.getTopSourceIPs(startDate, endDate, limit);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useTopASNs = (startDate?: string, endDate?: string, limit?: number) => {
  return useQuery({
    queryKey: ['analytics', 'top-asns', startDate, endDate, limit],
    queryFn: async () => {
      const { data } = await analyticsAPI.getTopASNs(startDate, endDate, limit);
      return data.data;
    },
    enabled: !!startDate && !!endDate,
  });
};

export const useSourceIPTimeline = (ip?: string) => {
  return useQuery({
    queryKey: ['analytics', 'ip-timeline', ip],
    queryFn: async () => {
      if (!ip) return [];
      const { data } = await analyticsAPI.getSourceIPTimeline(ip);
      return data.data;
    },
    enabled: !!ip,
  });
};
