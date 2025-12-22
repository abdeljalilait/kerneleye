//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// The event structure we send to userspace
struct event_t {
    u32 saddr; // Source IP (Remote)
    u32 daddr; // Dest IP (Local)
    u16 lport; // Local Port (e.g., 80, 443)
    u16 family; // AF_INET or AF_INET6
};

// Ring buffer to push events to Go
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Hook: kretprobe (Kernel Return Probe) on inet_csk_accept
// This function returns the NEW socket for an incoming connection.
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(detect_tcp_accept, struct sock *newsk) {
    if (newsk == NULL) {
        return 0; // Connection failed or no socket
    }

    // Cast to inet_sock to access IP details safely
    struct inet_sock *inet = (struct inet_sock *)newsk;
    struct event_t *e;

    // Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Read Source IP (Remote)
    // using BPF_CORE_READ macro for safety across kernel versions
    e->saddr = BPF_CORE_READ(inet, inet_saddr);
    
    // Read Destination IP (Local)
    e->daddr = BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr);

    // Read Local Port
    // Note: stored in network byte order in kernel
    e->lport = BPF_CORE_READ(inet, inet_sport);
    
    // Read Family (v4 vs v6)
    e->family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);

    // Filter: Only care about IPv4 for this MVP (AF_INET = 2)
    if (e->family != 2) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Submit to Go userspace
    bpf_ringbuf_submit(e, 0);

    return 0;
}



syntax = "proto3";

package trafficguard.v1;

option go_package = "./pb";

// The Agent Service definition.
service IngestService {
  // Agent sends a heartbeat every 30s to confirm it's alive
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  
  // Agent pushes aggregated traffic stats every N seconds
  rpc SubmitTraffic(TrafficBatch) returns (TrafficResponse);
}

message HeartbeatRequest {
  string api_key = 1;
  string hostname = 2;
  string agent_version = 3;
  double cpu_usage = 4; // Lightweight health check
  uint64 memory_usage = 5;
}

message HeartbeatResponse {
  bool success = 1;
  repeated string config_updates = 2; // e.g., "Change flush interval to 10s"
}

message TrafficBatch {
  string api_key = 1;
  int64 timestamp_start = 2; // Unix Epoch
  int64 timestamp_end = 3;   // Unix Epoch
  repeated ConnectionEvent events = 4;
}

message ConnectionEvent {
  string source_ip = 1;
  uint32 destination_port = 2;
  Protocol protocol = 3;
  
  // Metrics for this specific flow within the batch window
  uint32 syn_count = 4;
  uint32 ack_count = 5;
  uint64 bytes_in = 6;
  uint64 bytes_out = 7;
  bool is_failed_handshake = 8; // Did it SYN but never ACK?
}

enum Protocol {
  UNKNOWN = 0;
  TCP = 1;
  UDP = 2;
  ICMP = 3;
}

message TrafficResponse {
  bool success = 1;
  // In Phase 2, this response will contain IPs to block immediately
  repeated string block_directives = 2; 
}


import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  Server, 
  AlertTriangle, 
  Menu, 
  X, 
  CheckCircle, 
  Globe, 
  Cpu, 
  Terminal,
  Clock,
  ChevronRight,
  Search,
  Filter,
  MoreVertical
} from 'lucide-react';

/**
 * Traffic Guard - Dashboard Prototype
 * * This mock dashboard visualizes the data collected by the eBPF agents.
 * It focuses on the "Traffic Intelligence" aspect—showing risk scores
 * and live network events without overwhelming the user with raw logs.
 */

// --- Mock Data Generators ---

const generateTrafficData = () => {
  return Array.from({ length: 24 }, (_, i) => ({
    hour: `${i}:00`,
    inbound: Math.floor(Math.random() * 500) + 100,
    blocked: Math.floor(Math.random() * 50),
  }));
};

const MOCK_SERVERS = [
  { id: 'srv-01', name: 'app-production-01', ip: '142.93.12.5', status: 'active', load: '12%', lastSeen: 'Just now' },
  { id: 'srv-02', name: 'db-primary-01', ip: '142.93.12.8', status: 'active', load: '45%', lastSeen: 'Just now' },
  { id: 'srv-03', name: 'worker-queue-01', ip: '142.93.12.11', status: 'warning', load: '89%', lastSeen: '2m ago' },
];

const MOCK_ALERTS = [
  { id: 1, ip: '45.33.22.11', score: 85, reason: 'Port Scanning (TCP)', location: 'CN', time: '10s ago', status: 'active' },
  { id: 2, ip: '192.168.1.5', score: 42, reason: 'High SYN Rate', location: 'RU', time: '45s ago', status: 'active' },
  { id: 3, ip: '10.0.0.55', score: 25, reason: 'Failed Handshakes', location: 'US', time: '2m ago', status: 'monitoring' },
  { id: 4, ip: '185.22.1.4', score: 92, reason: 'SSH Brute Force', location: 'BR', time: '5m ago', status: 'active' },
  { id: 5, ip: '5.2.11.22', score: 15, reason: 'Burst Traffic', location: 'DE', time: '12m ago', status: 'cleared' },
];

const MOCK_LOGS = [
  { id: 101, src: '45.33.22.11', dst_port: 22, flag: 'SYN', action: 'FLAGGED' },
  { id: 102, src: '142.93.12.5', dst_port: 443, flag: 'ACK', action: 'ALLOW' },
  { id: 103, src: '88.12.43.11', dst_port: 80, flag: 'SYN', action: 'ALLOW' },
  { id: 104, src: '45.33.22.11', dst_port: 23, flag: 'SYN', action: 'FLAGGED' },
  { id: 105, src: '192.168.1.5', dst_port: 3306, flag: 'SYN', action: 'FLAGGED' },
];

// --- Components ---

const StatCard = ({ title, value, subtext, icon: Icon, trend }) => (
  <div className="bg-slate-800 border border-slate-700 p-5 md:p-6 rounded-lg shadow-sm hover:border-slate-600 transition-colors">
    <div className="flex items-start justify-between">
      <div>
        <p className="text-slate-400 text-sm font-medium mb-1">{title}</p>
        <h3 className="text-2xl font-bold text-white mb-1">{value}</h3>
        <p className={`text-xs ${trend === 'up' ? 'text-green-400' : trend === 'down' ? 'text-red-400' : 'text-slate-500'}`}>
          {subtext}
        </p>
      </div>
      <div className="p-2 bg-slate-700/50 rounded-md text-slate-300">
        <Icon size={20} />
      </div>
    </div>
  </div>
);

const RiskBadge = ({ score }) => {
  let colorClass = "bg-green-500/10 text-green-400 border-green-500/20";
  let label = "Clean";

  if (score >= 40) {
    colorClass = "bg-red-500/10 text-red-400 border-red-500/20";
    label = "Malicious";
  } else if (score >= 20) {
    colorClass = "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
    label = "Suspicious";
  }

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border whitespace-nowrap ${colorClass}`}>
      {score} - {label}
    </span>
  );
};

// Simple CSS Bar Chart for Traffic
const TrafficChart = () => {
  const data = generateTrafficData();
  const maxVal = Math.max(...data.map(d => d.inbound));

  return (
    <div className="h-48 md:h-64 flex items-end justify-between gap-1 mt-4">
      {data.map((d, i) => (
        <div key={i} className="flex-1 flex flex-col items-center group relative min-w-[2px]">
           {/* Tooltip */}
           <div className="absolute bottom-full mb-2 hidden group-hover:block bg-slate-900 text-xs p-2 rounded border border-slate-700 whitespace-nowrap z-10 pointer-events-none">
            {d.hour}: {d.inbound} reqs ({d.blocked} blocked)
          </div>
          <div className="w-full bg-slate-700/30 rounded-t-sm relative overflow-hidden" style={{ height: `${(d.inbound / maxVal) * 100}%` }}>
             <div 
               className="absolute bottom-0 w-full bg-indigo-500/80 hover:bg-indigo-400 transition-colors" 
               style={{ height: '100%' }}
             />
             <div 
               className="absolute bottom-0 w-full bg-red-500/80" 
               style={{ height: `${(d.blocked / d.inbound) * 100}%` }}
             />
          </div>
        </div>
      ))}
    </div>
  );
};

export default function TrafficGuardApp() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isSidebarOpen, setSidebarOpen] = useState(true);
  
  // Initialize sidebar state based on screen width
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth < 768) {
        setSidebarOpen(false);
      } else {
        setSidebarOpen(true);
      }
    };
    
    // Set initial
    handleResize();

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const navItems = [
    { id: 'dashboard', label: 'Overview', icon: Activity },
    { id: 'servers', label: 'Servers', icon: Server },
    { id: 'threats', label: 'Threats', icon: Shield },
    { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans flex overflow-hidden relative">
      
      {/* Mobile Sidebar Backdrop */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/60 z-20 md:hidden backdrop-blur-sm transition-opacity"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar 
          - Mobile: Fixed, Slides in/out, overlays content
          - Desktop: Relative, Collapses to mini-width, pushes content
      */}
      <aside 
        className={`
          fixed md:relative z-30 h-full bg-slate-900 border-r border-slate-800 transition-all duration-300 ease-in-out
          ${isSidebarOpen ? 'w-64 translate-x-0' : 'w-64 -translate-x-full md:w-20 md:translate-x-0'}
        `}
      >
        <div className="p-4 flex items-center justify-between border-b border-slate-800 h-16">
          <div className={`flex items-center gap-3 ${!isSidebarOpen && 'md:justify-center md:w-full'}`}>
            <div className="flex-shrink-0 w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center text-white font-bold shadow-lg shadow-indigo-500/20">
              <Shield size={18} />
            </div>
            <span className={`font-bold text-lg tracking-tight text-white transition-opacity duration-200 ${!isSidebarOpen && 'md:hidden'}`}>
              TrafficGuard
            </span>
          </div>
          {/* Mobile Close Button */}
          <button onClick={() => setSidebarOpen(false)} className="text-slate-500 hover:text-white md:hidden">
            <X size={20} />
          </button>
        </div>

        <nav className="flex-1 py-6 px-3 space-y-1">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setActiveTab(item.id);
                // On mobile, auto-close after selection
                if (window.innerWidth < 768) setSidebarOpen(false);
              }}
              className={`w-full flex items-center gap-3 px-3 py-3 rounded-md transition-all duration-200 group relative
                ${activeTab === item.id 
                  ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-600/20' 
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                } 
                ${!isSidebarOpen && 'md:justify-center'}
              `}
            >
              <item.icon size={20} className="flex-shrink-0" />
              
              <span className={`font-medium text-sm transition-opacity duration-200 ${!isSidebarOpen ? 'md:hidden' : 'block'}`}>
                {item.label}
              </span>

              {/* Tooltip for Mini Sidebar */}
              {!isSidebarOpen && (
                <div className="hidden md:group-hover:block absolute left-full ml-2 px-2 py-1 bg-slate-800 text-white text-xs rounded border border-slate-700 whitespace-nowrap z-50">
                  {item.label}
                </div>
              )}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-slate-800">
           <button 
             onClick={() => setSidebarOpen(!isSidebarOpen)}
             className={`w-full flex items-center gap-3 px-3 py-2 text-slate-500 hover:text-white transition-colors ${!isSidebarOpen && 'md:justify-center'}`}
           >
             <Menu size={20} className="flex-shrink-0" />
             <span className={`${!isSidebarOpen ? 'md:hidden' : 'block'} text-sm`}>Collapse</span>
           </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-full overflow-hidden bg-slate-950 w-full">
        
        {/* Top Header */}
        <header className="h-16 border-b border-slate-800 bg-slate-950 flex items-center justify-between px-4 md:px-6 flex-shrink-0">
          <div className="flex items-center gap-4">
            {/* Mobile Menu Trigger */}
            <button 
              onClick={() => setSidebarOpen(true)}
              className="md:hidden text-slate-400 hover:text-white p-1"
            >
              <Menu size={24} />
            </button>

            <h2 className="text-xl font-semibold text-white capitalize truncate">{activeTab}</h2>
            
            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 text-xs border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              System Healthy
            </span>
          </div>
          
          <div className="flex items-center gap-3 md:gap-4">
             <div className="hidden md:flex items-center gap-2 text-sm text-slate-400 bg-slate-900 py-1.5 px-3 rounded-full border border-slate-800">
                <Clock size={14} />
                <span>Just now</span>
             </div>
             <button className="md:hidden text-slate-400">
                <Search size={20} />
             </button>
             <div className="w-8 h-8 rounded-full bg-indigo-500/20 border border-indigo-500/50 flex items-center justify-center text-indigo-400 font-bold text-xs">
               JD
             </div>
          </div>
        </header>

        {/* Scrollable Dashboard Area */}
        <div className="flex-1 overflow-y-auto p-4 md:p-6 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
          
          <div className="max-w-7xl mx-auto space-y-6 pb-6">
            
            {/* KPI Stats Row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard 
                title="Monitored Servers" 
                value={MOCK_SERVERS.length.toString()} 
                subtext="All agents connected"
                icon={Server} 
                trend="neutral"
              />
              <StatCard 
                title="Active Threats" 
                value="12" 
                subtext="+3 in last hour"
                icon={AlertTriangle} 
                trend="up"
              />
              <StatCard 
                title="Blocked Requests" 
                value="1,429" 
                subtext="Last 24 hours"
                icon={Shield} 
                trend="neutral"
              />
              <StatCard 
                title="Traffic Volume" 
                value="450/s" 
                subtext="-12% vs avg"
                icon={Activity} 
                trend="down"
              />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Main Traffic Chart */}
              <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-4 md:p-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                  <div>
                    <h3 className="text-lg font-semibold text-white">Network Traffic</h3>
                    <p className="text-sm text-slate-400">Inbound packets (Aggregated)</p>
                  </div>
                  <div className="flex bg-slate-800 rounded-lg p-1 self-start sm:self-auto">
                     <button className="px-3 py-1 text-xs font-medium bg-slate-700 text-white rounded shadow-sm">24h</button>
                     <button className="px-3 py-1 text-xs font-medium text-slate-400 hover:text-white">7d</button>
                     <button className="px-3 py-1 text-xs font-medium text-slate-400 hover:text-white">30d</button>
                  </div>
                </div>
                <TrafficChart />
              </div>

              {/* Server List Status */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 md:p-6">
                <div className="flex items-center justify-between mb-4">
                   <h3 className="text-lg font-semibold text-white">Agent Status</h3>
                   <button className="text-xs text-indigo-400 hover:text-indigo-300">Manage</button>
                </div>
                <div className="space-y-3">
                  {MOCK_SERVERS.map(server => (
                    <div key={server.id} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-800">
                      <div className="flex items-center gap-3 overflow-hidden">
                        <div className={`flex-shrink-0 w-2 h-2 rounded-full ${server.status === 'active' ? 'bg-emerald-500' : 'bg-yellow-500'}`}></div>
                        <div className="truncate">
                          <p className="text-sm font-medium text-white truncate">{server.name}</p>
                          <p className="text-xs text-slate-500 font-mono">{server.ip}</p>
                        </div>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <p className="text-xs text-slate-400">Load: {server.load}</p>
                        <p className="text-[10px] text-slate-500">{server.lastSeen}</p>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-4 pt-4 border-t border-slate-800">
                   <button className="w-full py-2 flex items-center justify-center gap-2 text-sm text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors">
                     <Terminal size={14} /> Install New Agent
                   </button>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
               
               {/* High Risk IPs (The "Score" Feature) */}
               <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
                 <div className="p-4 md:p-6 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <h3 className="text-lg font-semibold text-white">Top Detected Threats</h3>
                      <p className="text-sm text-slate-400">IPs exceeding risk threshold</p>
                    </div>
                    <div className="relative w-full sm:w-auto">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={14} />
                      <input 
                        type="text" 
                        placeholder="Search IP..." 
                        className="w-full sm:w-48 bg-slate-950 border border-slate-700 rounded-full pl-9 pr-4 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                 </div>
                 
                 {/* Responsive Table Wrapper */}
                 <div className="overflow-x-auto scrollbar-thin scrollbar-thumb-slate-700">
                   <div className="min-w-[800px]"> {/* Force min width for table to prevent squishing */}
                    <table className="w-full text-left text-sm text-slate-400">
                        <thead className="bg-slate-950/50 text-xs uppercase font-semibold text-slate-500">
                        <tr>
                            <th className="px-6 py-4">Source IP / Location</th>
                            <th className="px-6 py-4">Reason</th>
                            <th className="px-6 py-4">Risk Score</th>
                            <th className="px-6 py-4">Last Active</th>
                            <th className="px-6 py-4 text-right">Action</th>
                        </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                        {MOCK_ALERTS.map(alert => (
                            <tr key={alert.id} className="hover:bg-slate-800/30 transition-colors">
                            <td className="px-6 py-4">
                                <div className="flex items-center gap-2">
                                <Globe size={14} className="text-slate-500" />
                                <span className="font-mono text-slate-300">{alert.ip}</span>
                                <span className="text-xs px-1.5 py-0.5 rounded bg-slate-800 text-slate-500">{alert.location}</span>
                                </div>
                            </td>
                            <td className="px-6 py-4 text-slate-300">{alert.reason}</td>
                            <td className="px-6 py-4">
                                <RiskBadge score={alert.score} />
                            </td>
                            <td className="px-6 py-4 text-slate-500">{alert.time}</td>
                            <td className="px-6 py-4 text-right">
                                <button className="text-xs font-medium text-indigo-400 hover:text-indigo-300 mr-3">Analyze</button>
                                <button className="text-xs font-medium text-red-400 hover:text-red-300">Block</button>
                            </td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                   </div>
                 </div>
               </div>

               {/* Live Stream / Terminal View */}
               <div className="bg-black border border-slate-800 rounded-xl overflow-hidden flex flex-col font-mono text-xs h-[300px] lg:h-auto">
                 <div className="bg-slate-900 px-4 py-3 border-b border-slate-800 flex items-center justify-between flex-shrink-0">
                    <span className="text-slate-400 flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                      Live Stream
                    </span>
                    <span className="text-[10px] text-slate-600">gRPC</span>
                 </div>
                 <div className="flex-1 p-4 space-y-2 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800 text-slate-300">
                   {MOCK_LOGS.map((log) => (
                     <div key={log.id} className="flex flex-wrap gap-x-2 gap-y-1 opacity-90 hover:opacity-100 border-b border-slate-900/50 pb-1 last:border-0 last:pb-0">
                       <span className="text-slate-600">[{new Date().toLocaleTimeString()}]</span>
                       <span className={`${log.action === 'FLAGGED' ? 'text-yellow-500' : 'text-green-500'}`}>
                         {log.action}
                       </span>
                       <div className="flex gap-1">
                        <span className="text-slate-400">{log.src}</span>
                        <span className="text-slate-600">→</span>
                        <span className="text-indigo-400">:{log.dst_port}</span>
                       </div>
                       <span className="text-slate-600">[{log.flag}]</span>
                     </div>
                   ))}
                   <div className="animate-pulse text-slate-600 pt-2">Waiting for packets...</div>
                 </div>
               </div>

            </div>
          </div>
        </div>
      </main>
    </div>
  );
}


package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the generate directive
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event_t bpf c/traffic_probe.c

func main() {
	// 1. Allow the current process to lock memory for eBPF maps.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// 2. Load the compiled eBPF objects into the kernel.
	// 'LoadBpfObjects' is generated by bpf2go in the adjacent file.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	// 3. Attach the Kretprobe to 'inet_csk_accept'
	// This triggers our C code whenever a TCP connection is accepted.
	kp, err := link.Kretprobe("inet_csk_accept", objs.DetectTcpAccept, nil)
	if err != nil {
		log.Fatalf("Failed to attach kretprobe: %v", err)
	}
	defer kp.Close()

	log.Println("Traffic Guard Agent Active...")
	log.Println("Listening for TCP connections (Ctrl+C to exit)")
	log.Println("------------------------------------------------")

	// 4. Open the Ring Buffer to receive events
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	// 5. Handle Exit Signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// 6. Event Loop
	go func() {
		<-c
		log.Println("Received signal, exiting...")
		rd.Close() // Breaks the loop below
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Ringbuf read error: %v", err)
			continue
		}

		// Parse the binary data into our struct
		var event bpfEventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to decode event: %v", err)
			continue
		}

		// Format Data for Display (Later: Send to API)
		remoteIP := intToIP(event.Saddr)
		localIP := intToIP(event.Daddr)
		// Port is Big Endian in kernel (network byte order), swap bytes for display
		localPort := swap16(event.Lport)

		fmt.Printf("[TCP] New Connection: %s -> %s:%d\n", 
			remoteIP, localIP, localPort)
	}
}

// Helpers for IP/Port conversion

func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

func swap16(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}



Traffic Guard Agent - Build Guide

This agent uses eBPF CO-RE (Compile Once, Run Everywhere). You need a Linux environment to build and run this.

Prerequisites

Linux Kernel 5.8+ (Recommended)

Clang/LLVM 12+ (sudo apt install clang llvm)

libbpf-dev (sudo apt install libbpf-dev)

Go 1.21+

Step 1: Generate vmlinux.h

We need the kernel type definitions to compile the C code.

bpftool btf dump file /sys/kernel/btf/vmlinux format c > c/vmlinux.h


Step 2: Generate Go Bindings

We use bpf2go to compile the C code and generate Go structs automatically.

go mod tidy
go generate


This will create bpf_bpfel.go and bpf_bpfel.o.

Step 3: Run

You must run as root to load eBPF programs.

go build -o agent
sudo ./agent


Testing

Run the agent.

In another terminal, make a connection: nc -zv localhost 22 (or connect to a web server).

You should see the log appear instantly in the agent output.