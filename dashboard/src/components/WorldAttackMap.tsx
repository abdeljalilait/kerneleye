import { useState, useMemo, useCallback } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  Line,
  ZoomableGroup,
} from 'react-simple-maps';
import { Typography, Space, Badge } from 'antd';
import { Server, Globe } from 'lucide-react';

const { Text } = Typography;

// World map topology - using a reliable CDN
const geoUrl = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';


interface WorldAttackMapProps {
  sourceIPs: Array<{
    ip: string;
    countryCode: string;
    country: string;
    count: number;
  }>;
  serverLocation?: {
    lat: number;
    lng: number;
    city: string;
    country: string;
  };
}

// Country coordinates lookup for major countries
const COUNTRY_COORDS: Record<string, { lat: number; lng: number }> = {
  US: { lat: 39.8283, lng: -98.5795 },
  CN: { lat: 35.8617, lng: 104.1954 },
  RU: { lat: 61.5240, lng: 105.3188 },
  DE: { lat: 51.1657, lng: 10.4515 },
  GB: { lat: 55.3781, lng: -3.4360 },
  FR: { lat: 46.2276, lng: 2.2137 },
  BR: { lat: -14.2350, lng: -51.9253 },
  IN: { lat: 20.5937, lng: 78.9629 },
  JP: { lat: 36.2048, lng: 138.2529 },
  KR: { lat: 35.9078, lng: 127.7669 },
  NL: { lat: 52.1326, lng: 5.2913 },
  SG: { lat: 1.3521, lng: 103.8198 },
  AU: { lat: -25.2744, lng: 133.7751 },
  CA: { lat: 56.1304, lng: -106.3468 },
  UA: { lat: 48.3794, lng: 31.1656 },
  PL: { lat: 51.9194, lng: 19.1451 },
  IT: { lat: 41.8719, lng: 12.5674 },
  ES: { lat: 40.4637, lng: -3.7492 },
  SE: { lat: 60.1282, lng: 18.6435 },
  CH: { lat: 46.8182, lng: 8.2275 },
  TR: { lat: 38.9637, lng: 35.2433 },
  ID: { lat: -0.7893, lng: 113.9213 },
  VN: { lat: 14.0583, lng: 108.2772 },
  TH: { lat: 15.8700, lng: 100.9925 },
  TW: { lat: 23.6978, lng: 120.9605 },
  HK: { lat: 22.3193, lng: 114.1694 },
  MX: { lat: 23.6345, lng: -102.5528 },
  AR: { lat: -38.4161, lng: -63.6167 },
  ZA: { lat: -30.5595, lng: 22.9375 },
  EG: { lat: 26.8206, lng: 30.8025 },
  NG: { lat: 9.0820, lng: 8.6753 },
  KE: { lat: -0.0236, lng: 37.9062 },
  IL: { lat: 31.0461, lng: 34.8516 },
  IR: { lat: 32.4279, lng: 53.6880 },
  SA: { lat: 23.8859, lng: 45.0792 },
  AE: { lat: 23.4241, lng: 53.8478 },
  PK: { lat: 30.3753, lng: 69.3451 },
  BD: { lat: 23.6850, lng: 90.3563 },
  RO: { lat: 45.9432, lng: 24.9668 },
  CZ: { lat: 49.8175, lng: 15.4730 },
  HU: { lat: 47.1625, lng: 19.5033 },
  AT: { lat: 47.5162, lng: 14.5501 },
  BE: { lat: 50.5039, lng: 4.4699 },
  DK: { lat: 56.2639, lng: 9.5018 },
  NO: { lat: 60.4720, lng: 8.4689 },
  FI: { lat: 61.9241, lng: 25.7482 },
  PT: { lat: 39.3999, lng: -8.2245 },
  GR: { lat: 39.0742, lng: 21.8243 },
  IE: { lat: 53.1424, lng: -7.6921 },
  NZ: { lat: -40.9006, lng: 174.8860 },
  MY: { lat: 4.2105, lng: 101.9758 },
  PH: { lat: 12.8797, lng: 121.7740 },
  CL: { lat: -35.6751, lng: -71.5430 },
  CO: { lat: 4.5709, lng: -74.2973 },
  PE: { lat: -9.1900, lng: -75.0152 },
  VE: { lat: 6.4238, lng: -66.5897 },
  EC: { lat: -1.8312, lng: -78.1834 },
  BO: { lat: -16.2902, lng: -63.5887 },
  PY: { lat: -23.4425, lng: -58.4438 },
  UY: { lat: -32.5228, lng: -55.7658 },
  KZ: { lat: 48.0196, lng: 66.9237 },
  UZ: { lat: 41.3775, lng: 64.5853 },
  AZ: { lat: 40.1431, lng: 47.5769 },
  AM: { lat: 40.0691, lng: 45.0382 },
  GE: { lat: 42.3154, lng: 43.3569 },
  BY: { lat: 53.7098, lng: 27.9534 },
  LT: { lat: 55.1694, lng: 23.8813 },
  LV: { lat: 56.8796, lng: 24.6032 },
  EE: { lat: 58.5953, lng: 25.0136 },
  MD: { lat: 47.4116, lng: 28.3699 },
  BG: { lat: 42.7339, lng: 25.4858 },
  RS: { lat: 44.0165, lng: 21.0059 },
  HR: { lat: 45.1000, lng: 15.2000 },
  SI: { lat: 46.1512, lng: 14.9955 },
  SK: { lat: 48.6690, lng: 19.6990 },
  BA: { lat: 43.9159, lng: 17.6791 },
  MK: { lat: 41.6086, lng: 21.7453 },
  AL: { lat: 41.1533, lng: 20.1683 },
  ME: { lat: 42.7087, lng: 19.3744 },
  CY: { lat: 35.1264, lng: 33.4299 },
  MT: { lat: 35.9375, lng: 14.3754 },
  IS: { lat: 64.9631, lng: -19.0208 },
  LU: { lat: 49.8153, lng: 6.1296 },
  MA: { lat: 31.7917, lng: -7.0926 },
  DZ: { lat: 28.0339, lng: 1.6596 },
  TN: { lat: 33.8869, lng: 9.5375 },
  LY: { lat: 26.3351, lng: 17.2283 },
  SD: { lat: 12.8628, lng: 30.2176 },
  ET: { lat: 9.1450, lng: 40.4897 },
  SO: { lat: 5.1521, lng: 46.1996 },
  TZ: { lat: -6.3690, lng: 34.8888 },
  UG: { lat: 1.3733, lng: 32.2903 },
  RW: { lat: -1.9403, lng: 29.8739 },
  BI: { lat: -3.3731, lng: 29.9189 },
  MW: { lat: -13.2543, lng: 34.3015 },
  MZ: { lat: -18.6657, lng: 35.5296 },
  ZM: { lat: -13.1339, lng: 27.8493 },
  ZW: { lat: -19.0154, lng: 29.1549 },
  BW: { lat: -22.3285, lng: 24.6849 },
  NA: { lat: -22.9576, lng: 18.4904 },
  AO: { lat: -11.2027, lng: 17.8739 },
  CD: { lat: -4.0383, lng: 21.7587 },
  CG: { lat: -0.2280, lng: 15.8277 },
  GA: { lat: -0.8037, lng: 11.6094 },
  GQ: { lat: 1.6508, lng: 10.2679 },
  CM: { lat: 7.3697, lng: 12.3547 },
  CF: { lat: 6.6111, lng: 20.9394 },
  TD: { lat: 15.4542, lng: 18.7322 },
  NE: { lat: 17.6078, lng: 8.0817 },
  ML: { lat: 17.5707, lng: -3.9962 },
  BF: { lat: 12.2383, lng: -1.5616 },
  SN: { lat: 14.4974, lng: -14.4524 },
  GM: { lat: 13.4432, lng: -15.3101 },
  GN: { lat: 9.9456, lng: -9.6966 },
  SL: { lat: 8.4606, lng: -11.7799 },
  LR: { lat: 6.4281, lng: -9.4295 },
  CI: { lat: 7.5400, lng: -5.5471 },
  GH: { lat: 7.9465, lng: -1.0232 },
  TG: { lat: 8.6195, lng: 0.8248 },
  BJ: { lat: 9.3077, lng: 2.3158 },
  MR: { lat: 21.0079, lng: -10.9408 },
  SS: { lat: 6.8770, lng: 31.3070 },
  ER: { lat: 15.1794, lng: 39.7823 },
  DJ: { lat: 11.8251, lng: 42.5903 },
  MU: { lat: -20.3484, lng: 57.5522 },
  MG: { lat: -18.7669, lng: 46.8691 },
};

// Get coordinates for a country code
function getCountryCoords(countryCode: string): { lat: number; lng: number } | null {
  const coords = COUNTRY_COORDS[countryCode?.toUpperCase()];
  return coords || null;
}

// Calculate distance between two points in km
function calculateDistance(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const R = 6371; // Earth's radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLng / 2) * Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c);
}

export default function WorldAttackMap({ sourceIPs, serverLocation }: WorldAttackMapProps) {
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  const hasServerLocation = !!serverLocation;
  // Only use coordinates if we have a real location
  const serverLoc = serverLocation;

  // Group attack points by country
  const attackPointsByCountry = useMemo(() => {
    const groups = new Map<string, { count: number; ips: string[] }>();
    
    sourceIPs.forEach((ip) => {
      const coords = getCountryCoords(ip.countryCode);
      if (!coords) return;
      
      const countryCode = ip.countryCode.toUpperCase();
      const existing = groups.get(countryCode);
      
      if (existing) {
        existing.count += ip.count;
        existing.ips.push(ip.ip);
      } else {
        groups.set(countryCode, { count: ip.count, ips: [ip.ip] });
      }
    });
    
    return Array.from(groups.entries()).map(([countryCode, data]) => ({
      countryCode,
      ...data,
      ...getCountryCoords(countryCode)!,
    }));
  }, [sourceIPs]);

  // Calculate total attacks
  const totalAttacks = attackPointsByCountry.reduce((sum, p) => sum + p.count, 0);

  // Get top attacker
  const topAttacker = attackPointsByCountry.sort((a, b) => b.count - a.count)[0];

  // Handle mouse move for custom tooltip
  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    setTooltipPos({ x: e.clientX, y: e.clientY - 40 });
  }, []);

  return (
    <div 
      style={{ position: 'relative', width: '100%', height: '100%', minHeight: 560 }}
      onMouseMove={handleMouseMove}
    >
      {/* Header */}
      <div style={{ 
        position: 'absolute', 
        top: 12, 
        left: 16, 
        zIndex: 10,
        display: 'flex',
        alignItems: 'center',
        gap: 12,
      }}>
        <div style={{
          width: 36,
          height: 36,
          background: 'rgba(99, 102, 241, 0.15)',
          borderRadius: 10,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <Globe size={18} color="#6366f1" />
        </div>
        <div>
          <Text strong style={{ color: 'var(--text-primary)', fontSize: 14 }}>
            Global Attack Map
          </Text>
          <Text style={{ color: 'var(--text-tertiary)', fontSize: 12, display: 'block' }}>
            {attackPointsByCountry.length} countries • {totalAttacks.toLocaleString()} attacks
          </Text>
        </div>
      </div>

      {/* Server Location Badge */}
      <div style={{ 
        position: 'absolute', 
        top: 12, 
        right: 16, 
        zIndex: 10,
      }}>
        {hasServerLocation && serverLoc ? (
          <Space size={8}>
            <Badge status="processing" color="#10b981" />
            <div style={{
              padding: '6px 12px',
              background: 'rgba(16, 185, 129, 0.15)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              borderRadius: 20,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}>
              <Server size={14} color="#10b981" />
              <Text style={{ color: '#10b981', fontSize: 12, fontWeight: 500 }}>
                Your Server: {serverLoc.city}{serverLoc.country ? `, ${serverLoc.country}` : ''}
              </Text>
            </div>
          </Space>
        ) : (
          <div style={{
            padding: '6px 12px',
            background: 'rgba(100,116,139,0.1)',
            border: '1px solid rgba(100,116,139,0.2)',
            borderRadius: 20,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}>
            <Server size={14} color="#64748b" />
            <Text style={{ color: '#64748b', fontSize: 12 }}>Server location unknown</Text>
          </div>
        )}
      </div>

      {/* React Simple Maps */}
      <ComposableMap
        projection="geoMercator"
        projectionConfig={{
          scale: 147,
          center: [0, 20],
        }}
        style={{
          width: '100%',
          height: '100%',
          background: 'linear-gradient(180deg, rgba(10,10,15,0.95) 0%, rgba(20,20,35,0.9) 100%)',
        }}
      >
        <ZoomableGroup zoom={1} minZoom={1} maxZoom={8} center={[0, 20]}>
          {/* World Geographies */}
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies.map((geo) => {
                const countryCode = geo.properties.ISO_A2;
                const hasAttacks = attackPointsByCountry.some(p => p.countryCode === countryCode);
                
                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    onMouseEnter={() => setHoveredCountry(countryCode)}
                    onMouseLeave={() => setHoveredCountry(null)}
                    style={{
                      default: {
                        fill: hasAttacks ? 'rgba(239, 68, 68, 0.3)' : 'rgba(99, 102, 241, 0.1)',
                        stroke: 'rgba(99, 102, 241, 0.3)',
                        strokeWidth: 0.5,
                        outline: 'none',
                      },
                      hover: {
                        fill: hasAttacks ? 'rgba(239, 68, 68, 0.5)' : 'rgba(99, 102, 241, 0.25)',
                        stroke: 'rgba(99, 102, 241, 0.5)',
                        strokeWidth: 0.5,
                        outline: 'none',
                        cursor: 'pointer',
                      },
                      pressed: {
                        fill: 'rgba(99, 102, 241, 0.3)',
                        outline: 'none',
                      },
                    }}
                  />
                );
              })
            }
          </Geographies>

          {/* Attack source lines – only draw when server location is known */}
          {hasServerLocation && serverLoc && attackPointsByCountry.slice(0, 15).map((point) => (
            <Line
              key={`line-${point.countryCode}`}
              from={[point.lng, point.lat]}
              to={[serverLoc.lng, serverLoc.lat]}
              stroke="rgba(239, 68, 68, 0.4)"
              strokeWidth={Math.max(0.5, Math.log10(point.count) * 0.8)}
              strokeLinecap="round"
              style={{
                filter: hoveredCountry === point.countryCode ? 'drop-shadow(0 0 4px #ef4444)' : 'none',
              }}
            />
          ))}

          {/* Attack source markers */}
          {attackPointsByCountry.map((point) => {
            const isHovered = hoveredCountry === point.countryCode;
            const radius = Math.max(4, Math.min(12, Math.log10(point.count) * 3));
            
            return (
              <Marker key={point.countryCode} coordinates={[point.lng, point.lat]}>
                <g
                  onMouseEnter={() => setHoveredCountry(point.countryCode)}
                  onMouseLeave={() => setHoveredCountry(null)}
                  style={{ cursor: 'pointer' }}
                >
                  {/* Outer glow */}
                  <circle
                    r={radius * 2}
                    fill="rgba(239, 68, 68, 0.2)"
                    style={{
                      transform: isHovered ? 'scale(1.2)' : 'scale(1)',
                      transition: 'transform 0.2s',
                    }}
                  />
                  {/* Main circle */}
                  <circle
                    r={radius}
                    fill={isHovered ? '#ef4444' : 'rgba(239, 68, 68, 0.9)'}
                    stroke="#fff"
                    strokeWidth={isHovered ? 2 : 1}
                    style={{
                      filter: isHovered ? 'drop-shadow(0 0 6px #ef4444)' : 'none',
                    }}
                  />
                  {/* Count label for major attacks */}
                  {point.count > 50 && (
                    <text
                      y={radius + 12}
                      textAnchor="middle"
                      fill="#ef4444"
                      fontSize="9"
                      fontWeight="bold"
                    >
                      {point.count > 999 ? '999+' : point.count}
                    </text>
                  )}
                </g>
              </Marker>
            );
          })}

          {/* Server location marker – only render when location is known */}
          {hasServerLocation && serverLoc && (
            <Marker coordinates={[serverLoc.lng, serverLoc.lat]}>
              <g>
                {/* Pulse rings */}
                <circle r="20" fill="none" stroke="#10b981" strokeWidth="1" opacity="0.3">
                  <animate
                    attributeName="r"
                    from="10"
                    to="30"
                    dur="2s"
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="opacity"
                    from="0.6"
                    to="0"
                    dur="2s"
                    repeatCount="indefinite"
                  />
                </circle>
                <circle r="16" fill="none" stroke="#10b981" strokeWidth="1" opacity="0.4">
                  <animate
                    attributeName="r"
                    from="8"
                    to="24"
                    dur="2s"
                    begin="0.5s"
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="opacity"
                    from="0.5"
                    to="0"
                    dur="2s"
                    begin="0.5s"
                    repeatCount="indefinite"
                  />
                </circle>
                {/* Server icon background */}
                <circle r="10" fill="rgba(16,185,129,0.2)" stroke="#10b981" strokeWidth="2" />
                {/* Inner dot */}
                <circle r="5" fill="#10b981" />
              </g>
            </Marker>
          )}
        </ZoomableGroup>
      </ComposableMap>

      {/* Legend */}
      <div style={{
        position: 'absolute',
        bottom: 16,
        left: 16,
        display: 'flex',
        gap: 20,
        background: 'rgba(0,0,0,0.6)',
        padding: '8px 16px',
        borderRadius: 20,
        backdropFilter: 'blur(4px)',
      }}>
        <Space size={8}>
          <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444' }} />
          <Text style={{ color: 'var(--text-secondary)', fontSize: 11 }}>Attack Source</Text>
        </Space>
        {hasServerLocation && (
          <>
            <Space size={8}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#10b981' }} />
              <Text style={{ color: 'var(--text-secondary)', fontSize: 11 }}>Your Server</Text>
            </Space>
            <Space size={8}>
              <div style={{ width: 20, height: 2, background: 'rgba(239,68,68,0.4)' }} />
              <Text style={{ color: 'var(--text-secondary)', fontSize: 11 }}>Attack Path</Text>
            </Space>
          </>
        )}
      </div>

      {/* Stats overlay */}
      {topAttacker && (
        <div style={{
          position: 'absolute',
          bottom: 16,
          right: 16,
          background: 'rgba(0,0,0,0.6)',
          padding: '12px 16px',
          borderRadius: 12,
          backdropFilter: 'blur(4px)',
          minWidth: 180,
        }}>
          <Space direction="vertical" size={6} style={{ width: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>Top Source:</Text>
              <Text style={{ color: '#ef4444', fontSize: 12, fontWeight: 600 }}>
                {topAttacker.countryCode}
              </Text>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>Attacks:</Text>
              <Text style={{ color: 'var(--text-secondary)', fontSize: 12, fontWeight: 600 }}>
                {topAttacker.count.toLocaleString()}
              </Text>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>Distance:</Text>
              <Text style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                {hasServerLocation && serverLoc
                  ? `${calculateDistance(topAttacker.lat, topAttacker.lng, serverLoc.lat, serverLoc.lng).toLocaleString()} km`
                  : 'N/A'}
              </Text>
            </div>
          </Space>
        </div>
      )}

      {/* Custom Tooltip */}
      {hoveredCountry && (
        <div
          style={{
            position: 'fixed',
            left: tooltipPos.x,
            top: tooltipPos.y,
            background: 'rgba(0,0,0,0.9)',
            border: '1px solid rgba(99,102,241,0.3)',
            borderRadius: 8,
            padding: '8px 12px',
            pointerEvents: 'none',
            zIndex: 1000,
            transform: 'translate(-50%, -100%)',
          }}
        >
          {(() => {
            const point = attackPointsByCountry.find(p => p.countryCode === hoveredCountry);
            if (point) {
              return (
                <Space direction="vertical" size={2}>
                  <Text strong style={{ color: '#fff', fontSize: 13 }}>
                    {point.countryCode}
                  </Text>
                  <Text style={{ color: '#ef4444', fontSize: 12 }}>
                    {point.count.toLocaleString()} attacks
                  </Text>
                  <Text style={{ color: 'var(--text-tertiary)', fontSize: 11 }}>
                    {point.ips.length} IP{point.ips.length > 1 ? 's' : ''}
                  </Text>
                </Space>
              );
            }
            return (
              <Text style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>
                {hoveredCountry}
              </Text>
            );
          })()}
        </div>
      )}
    </div>
  );
}
