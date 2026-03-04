package services

// portToService maps well-known destination ports to their application-layer service name.
var portToService = map[int]string{
21:    "FTP",
22:    "SSH",
23:    "Telnet",
25:    "SMTP",
53:    "DNS",
67:    "DHCP",
68:    "DHCP",
80:    "HTTP",
110:   "POP3",
143:   "IMAP",
161:   "SNMP",
389:   "LDAP",
443:   "HTTPS",
587:   "SMTP",
636:   "LDAPS",
993:   "IMAPS",
995:   "POP3S",
1194:  "OpenVPN",
3000:  "HTTP-Alt",
3306:  "MySQL",
3389:  "RDP",
5432:  "PostgreSQL",
6379:  "Redis",
8000:  "HTTP-Alt",
8080:  "HTTP-Alt",
8443:  "HTTPS-Alt",
27017: "MongoDB",
}

// processToService maps well-known daemon/process names to their service label.
// Process-name identification works correctly regardless of port number (e.g. sshd on port 2222).
var processToService = map[string]string{
"sshd":          "SSH",
"nginx":         "HTTP",
"apache2":       "HTTP",
"httpd":         "HTTP",
"lighttpd":      "HTTP",
"caddy":         "HTTP",
"mysqld":        "MySQL",
"mariadbd":      "MySQL",
"postgres":      "PostgreSQL",
"redis-server":  "Redis",
"mongod":        "MongoDB",
"named":         "DNS",
"unbound":       "DNS",
"dnsmasq":       "DNS",
"vsftpd":        "FTP",
"proftpd":       "FTP",
"pure-ftpd":     "FTP",
"postfix":       "SMTP",
"sendmail":      "SMTP",
"dovecot":       "IMAP/POP3",
"xrdp":          "RDP",
"telnetd":       "Telnet",
"memcached":     "Memcached",
"rabbitmq":      "RabbitMQ",
"kafka":         "Kafka",
"elasticsearch": "Elasticsearch",
}

// ServiceFromPort returns the application-layer service name for a well-known port,
// or an empty string when the port is not recognised.
func ServiceFromPort(port int) string {
return portToService[port]
}

// ResolveService returns the application-layer service name using three-level priority:
//  1. Process name from eBPF comm field (works for custom ports, e.g. sshd on 2222)
//  2. Well-known port number lookup
//  3. L4 protocol string as last resort (e.g. "TCP", "UDP")
func ResolveService(processName string, port int, protocol string) string {
if processName != "" {
if svc, ok := processToService[processName]; ok {
return svc
}
}
if svc := ServiceFromPort(port); svc != "" {
return svc
}
return protocol
}
