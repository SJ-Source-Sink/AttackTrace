"""
Security guidance for discovered services and ports.

Provides detailed security implications, attack vectors, and remediation
guidance for common exposed services. Used in reports to help defenders
understand and prioritize remediation.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceGuidance:
    """Security guidance for a specific service type."""
    service_name: str
    risk_level: str  # critical, high, medium, low, info
    description: str
    security_implications: list[str]
    common_attack_vectors: list[str]
    remediation_steps: list[str]
    detection_tips: list[str]
    references: list[str]
    default_credentials: list[str] = None
    related_cves: list[str] = None
    tools_for_testing: list[str] = None


# Comprehensive security guidance for common services
SERVICE_GUIDANCE = {
    # =========================================================================
    # DATABASES
    # =========================================================================
    27017: ServiceGuidance(
        service_name="MongoDB",
        risk_level="critical",
        description="MongoDB is a NoSQL document database. When exposed without authentication, it allows complete database access.",
        security_implications=[
            "Complete read/write access to all databases and collections",
            "Data exfiltration of sensitive information (PII, credentials, business data)",
            "Data manipulation or deletion (ransomware attacks common)",
            "Server-side JavaScript execution via $where queries",
            "Potential for lateral movement if credentials are stored",
        ],
        common_attack_vectors=[
            "Direct connection without authentication (mongo <ip>:27017)",
            "Enumeration of databases: show dbs, show collections",
            "Data dump: mongoexport or mongodump",
            "Ransomware: Drop databases, leave ransom note",
            "Credential harvesting from stored user data",
        ],
        remediation_steps=[
            "Enable authentication: use SCRAM-SHA-256",
            "Bind to localhost or internal interfaces only (bindIp: 127.0.0.1)",
            "Enable TLS/SSL for connections",
            "Use firewall rules to restrict access to trusted IPs",
            "Enable audit logging for compliance",
            "Disable server-side JavaScript (security.javascriptEnabled: false)",
            "Regular backups with tested restore procedures",
        ],
        detection_tips=[
            "Monitor for connections from unexpected IPs",
            "Alert on 'show dbs' or bulk data operations",
            "Check for new admin users or role changes",
            "Monitor for large data transfers",
        ],
        references=[
            "https://www.mongodb.com/docs/manual/security/",
            "https://attack.mitre.org/techniques/T1190/",
            "https://www.shodan.io/search?query=mongodb",
        ],
        default_credentials=["No authentication by default"],
        tools_for_testing=["mongo CLI", "mongodump", "Nmap mongodb-info script", "Metasploit mongodb_login"],
    ),

    6379: ServiceGuidance(
        service_name="Redis",
        risk_level="critical",
        description="Redis is an in-memory data structure store. Unprotected Redis allows data access and potential server compromise.",
        security_implications=[
            "Read/write access to all cached data",
            "Session hijacking if sessions are stored in Redis",
            "Remote code execution via CONFIG SET dir/dbfilename (write SSH keys or cron)",
            "Denial of service via FLUSHALL",
            "Credential theft from cached authentication tokens",
        ],
        common_attack_vectors=[
            "Direct connection: redis-cli -h <ip>",
            "Data enumeration: KEYS *, GET <key>",
            "RCE via SSH key injection: CONFIG SET dir /root/.ssh; SET authorized_keys '<ssh-key>'; SAVE",
            "RCE via cron job injection",
            "RCE via webshell if web directory is writable",
            "Lua script execution for advanced attacks",
        ],
        remediation_steps=[
            "Enable authentication: requirepass <strong-password>",
            "Bind to localhost: bind 127.0.0.1",
            "Disable dangerous commands: rename-command CONFIG ''",
            "Enable TLS for connections (Redis 6+)",
            "Use Redis ACLs for granular access control (Redis 6+)",
            "Run Redis as non-root user",
            "Use firewall rules to restrict access",
        ],
        detection_tips=[
            "Monitor CONFIG SET commands",
            "Alert on FLUSHALL/FLUSHDB operations",
            "Watch for suspicious EVAL (Lua) commands",
            "Monitor for large KEYS operations",
        ],
        references=[
            "https://redis.io/docs/management/security/",
            "https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis",
        ],
        default_credentials=["No authentication by default"],
        related_cves=["CVE-2022-0543 (Lua sandbox escape)", "CVE-2015-8080 (Integer overflow)"],
        tools_for_testing=["redis-cli", "Nmap redis-info script", "redis-rogue-server"],
    ),

    9200: ServiceGuidance(
        service_name="Elasticsearch",
        risk_level="high",
        description="Elasticsearch is a distributed search and analytics engine. Exposed instances leak indexed data.",
        security_implications=[
            "Read access to all indexed data (logs, documents, metrics)",
            "Write access can corrupt or delete indices",
            "Sensitive data exposure (PII, logs with credentials, business data)",
            "Scripting can lead to code execution (older versions)",
            "Cluster manipulation and denial of service",
        ],
        common_attack_vectors=[
            "Index enumeration: GET /_cat/indices",
            "Data access: GET /<index>/_search?q=*",
            "Bulk data dump via scroll API",
            "Script injection (deprecated but check older versions)",
            "Snapshot repository abuse for data exfiltration",
        ],
        remediation_steps=[
            "Enable X-Pack Security (authentication and TLS)",
            "Use role-based access control (RBAC)",
            "Bind to localhost or internal network",
            "Enable TLS for transport and HTTP layers",
            "Disable dynamic scripting if not needed",
            "Use firewall rules and network segmentation",
            "Enable audit logging",
        ],
        detection_tips=[
            "Monitor for _cat/indices or _search requests from unknown IPs",
            "Alert on bulk scroll operations",
            "Watch for index deletion attempts",
            "Monitor cluster settings changes",
        ],
        references=[
            "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
            "https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch",
        ],
        default_credentials=["No authentication by default (without X-Pack)"],
        tools_for_testing=["curl", "Elasticdump", "Nmap elasticsearch scripts"],
    ),

    3306: ServiceGuidance(
        service_name="MySQL",
        risk_level="high",
        description="MySQL is a popular relational database. Exposed MySQL may allow unauthorized data access or server compromise.",
        security_implications=[
            "Database enumeration and data theft",
            "Credential brute-forcing",
            "SQL injection if application layer is also vulnerable",
            "File read via LOAD DATA INFILE",
            "File write via INTO OUTFILE (webshell deployment)",
            "UDF (User Defined Function) for code execution",
        ],
        common_attack_vectors=[
            "Brute force: hydra, medusa, mysql_login",
            "Anonymous/root login attempts",
            "Data enumeration: SHOW DATABASES; SHOW TABLES;",
            "Privilege escalation via UDF",
            "File operations: SELECT LOAD_FILE('/etc/passwd')",
        ],
        remediation_steps=[
            "Remove anonymous users and test databases",
            "Set strong passwords for all accounts",
            "Bind to localhost (bind-address = 127.0.0.1)",
            "Use SSL/TLS for connections",
            "Implement least privilege access",
            "Disable FILE privilege for non-admin users",
            "Use firewall rules to restrict access",
            "Enable audit logging",
        ],
        detection_tips=[
            "Monitor failed login attempts",
            "Alert on connections from unexpected hosts",
            "Watch for LOAD_FILE or INTO OUTFILE queries",
            "Monitor for privilege changes",
        ],
        references=[
            "https://dev.mysql.com/doc/refman/8.0/en/security.html",
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql",
        ],
        default_credentials=["root (no password)", "root:root", "root:mysql", "mysql:mysql"],
        related_cves=["CVE-2012-2122 (Authentication bypass)"],
        tools_for_testing=["mysql CLI", "Nmap mysql scripts", "Hydra", "SQLMap"],
    ),

    5432: ServiceGuidance(
        service_name="PostgreSQL",
        risk_level="high",
        description="PostgreSQL is an advanced relational database. Exposed PostgreSQL may allow data theft or server compromise.",
        security_implications=[
            "Database access and data exfiltration",
            "Credential brute-forcing",
            "Command execution via COPY TO/FROM PROGRAM",
            "File read/write operations",
            "Extension-based attacks (e.g., pg_execute_server_program)",
        ],
        common_attack_vectors=[
            "Brute force with common credentials",
            "COPY TO PROGRAM for command execution (superuser)",
            "Large object manipulation for file operations",
            "Extension exploitation",
            "pg_read_file() for sensitive file access",
        ],
        remediation_steps=[
            "Configure pg_hba.conf to restrict connections",
            "Use strong passwords and disable trust authentication",
            "Bind to localhost (listen_addresses = 'localhost')",
            "Enable SSL/TLS connections",
            "Implement row-level security",
            "Remove unnecessary extensions",
            "Regular security updates",
            "Enable logging and monitoring",
        ],
        detection_tips=[
            "Monitor COPY PROGRAM commands",
            "Alert on pg_read_file or lo_* operations",
            "Watch for superuser login attempts",
            "Track extension installations",
        ],
        references=[
            "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql",
        ],
        default_credentials=["postgres:postgres", "postgres (no password)"],
        tools_for_testing=["psql", "pgcli", "Nmap pgsql scripts", "Metasploit postgres modules"],
    ),

    11211: ServiceGuidance(
        service_name="Memcached",
        risk_level="medium",
        description="Memcached is a distributed memory caching system. Exposed Memcached leaks cached data and enables amplification attacks.",
        security_implications=[
            "Cached data exposure (sessions, credentials, API responses)",
            "Session hijacking via cached session data",
            "DDoS amplification attacks (UDP reflection)",
            "Cache poisoning",
        ],
        common_attack_vectors=[
            "Data enumeration: stats items, stats cachedump",
            "Key retrieval: get <key>",
            "UDP amplification for DDoS",
            "Cache poisoning to inject malicious data",
        ],
        remediation_steps=[
            "Bind to localhost (-l 127.0.0.1)",
            "Disable UDP protocol (-U 0)",
            "Use SASL authentication",
            "Use firewall rules to restrict access",
            "Consider using encrypted connections (stunnel/TLS proxy)",
            "Implement network segmentation",
        ],
        detection_tips=[
            "Monitor for stats/cachedump commands",
            "Watch for UDP traffic spikes (amplification)",
            "Alert on connections from unexpected sources",
        ],
        references=[
            "https://github.com/memcached/memcached/wiki/ConfiguringServer",
            "https://www.cloudflare.com/learning/ddos/memcached-ddos-attack/",
        ],
        default_credentials=["No authentication by default"],
        tools_for_testing=["memccat", "memcdump", "Nmap memcached-info"],
    ),

    # =========================================================================
    # REMOTE ACCESS
    # =========================================================================
    3389: ServiceGuidance(
        service_name="RDP (Remote Desktop)",
        risk_level="high",
        description="Remote Desktop Protocol enables remote Windows access. Exposed RDP is a prime target for brute force and exploitation.",
        security_implications=[
            "Brute force attacks for credential theft",
            "BlueKeep and related RCE vulnerabilities",
            "Ransomware deployment vector",
            "Lateral movement within networks",
            "Session hijacking",
        ],
        common_attack_vectors=[
            "Credential brute forcing (hydra, crowbar, ncrack)",
            "BlueKeep exploitation (CVE-2019-0708)",
            "Pass-the-hash attacks",
            "RDP session hijacking",
            "Man-in-the-middle via RDP downgrade",
        ],
        remediation_steps=[
            "Never expose RDP directly to internet",
            "Use VPN or Remote Desktop Gateway",
            "Enable Network Level Authentication (NLA)",
            "Use strong, unique passwords",
            "Implement account lockout policies",
            "Enable MFA where possible",
            "Keep systems patched (BlueKeep, etc.)",
            "Use firewall to restrict source IPs",
            "Enable RDP logging and monitoring",
        ],
        detection_tips=[
            "Monitor for failed login attempts (Event ID 4625)",
            "Alert on successful logins from unusual IPs",
            "Watch for connections outside business hours",
            "Track RDP session events (Event IDs 4778, 4779)",
        ],
        references=[
            "https://attack.mitre.org/techniques/T1021/001/",
            "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-plan-secure",
        ],
        related_cves=["CVE-2019-0708 (BlueKeep)", "CVE-2019-1181/1182 (DejaBlue)"],
        tools_for_testing=["Nmap rdp scripts", "Hydra", "Crowbar", "xfreerdp"],
    ),

    5900: ServiceGuidance(
        service_name="VNC",
        risk_level="high",
        description="VNC provides remote desktop access. Exposed VNC often has weak authentication and transmits data in cleartext.",
        security_implications=[
            "Brute force attacks (many VNC servers have weak passwords)",
            "Screenshot/keylogging of remote sessions",
            "Complete system control if accessed",
            "No encryption by default (credentials visible on network)",
        ],
        common_attack_vectors=[
            "Password brute forcing",
            "Default/blank password exploitation",
            "Authentication bypass vulnerabilities",
            "Traffic interception (cleartext protocol)",
        ],
        remediation_steps=[
            "Never expose VNC directly to internet",
            "Use VPN or SSH tunnel for VNC access",
            "Set strong passwords",
            "Enable VNC encryption where available",
            "Use firewall to restrict access",
            "Consider alternatives like RDP with NLA",
        ],
        detection_tips=[
            "Monitor for multiple failed authentication attempts",
            "Alert on VNC connections from unexpected IPs",
            "Watch for long-running VNC sessions",
        ],
        references=[
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-vnc",
        ],
        default_credentials=["(blank)", "password", "vnc", "1234"],
        tools_for_testing=["vncviewer", "Hydra vnc module", "Nmap vnc scripts"],
    ),

    22: ServiceGuidance(
        service_name="SSH",
        risk_level="info",
        description="SSH provides secure remote access. While generally secure, misconfigurations can lead to compromise.",
        security_implications=[
            "Brute force attacks if password authentication enabled",
            "Key-based attacks if keys are weak or leaked",
            "Version-specific vulnerabilities",
            "Credential reuse if same keys/passwords used elsewhere",
        ],
        common_attack_vectors=[
            "Password brute forcing",
            "Username enumeration (older versions)",
            "Stolen/leaked SSH keys",
            "Agent forwarding abuse",
        ],
        remediation_steps=[
            "Disable password authentication (use keys only)",
            "Use strong SSH keys (Ed25519 or RSA 4096+)",
            "Implement fail2ban or similar",
            "Change default port (security through obscurity, limited value)",
            "Restrict users with AllowUsers/AllowGroups",
            "Disable root login (PermitRootLogin no)",
            "Keep SSH updated",
            "Use certificate-based authentication for large deployments",
        ],
        detection_tips=[
            "Monitor auth.log for failed attempts",
            "Alert on successful logins from new IPs",
            "Watch for logins outside normal hours",
            "Track authorized_keys modifications",
        ],
        references=[
            "https://www.ssh.com/academy/ssh/security",
            "https://attack.mitre.org/techniques/T1021/004/",
        ],
        tools_for_testing=["ssh-audit", "Nmap ssh scripts", "Hydra"],
    ),

    23: ServiceGuidance(
        service_name="Telnet",
        risk_level="high",
        description="Telnet is an unencrypted remote access protocol. All traffic, including credentials, is transmitted in cleartext.",
        security_implications=[
            "Credentials transmitted in cleartext (trivial to intercept)",
            "No encryption - all commands visible",
            "Often has default credentials on network devices",
            "Brute force attacks",
        ],
        common_attack_vectors=[
            "Credential sniffing on network",
            "Default credential exploitation",
            "Brute force attacks",
            "Man-in-the-middle attacks",
        ],
        remediation_steps=[
            "Replace Telnet with SSH immediately",
            "If Telnet required, restrict to management VLAN only",
            "Use strong, unique credentials",
            "Monitor and log all Telnet access",
            "Implement network segmentation",
        ],
        detection_tips=[
            "Alert on any Telnet traffic on network",
            "Monitor for default credential usage",
            "Watch for brute force attempts",
        ],
        references=[
            "https://attack.mitre.org/techniques/T1021/",
        ],
        default_credentials=["admin:admin", "root:root", "cisco:cisco", "admin:password"],
        tools_for_testing=["telnet", "Nmap telnet scripts", "Hydra"],
    ),

    # =========================================================================
    # FILE SHARING
    # =========================================================================
    445: ServiceGuidance(
        service_name="SMB",
        risk_level="critical",
        description="SMB is Windows file sharing protocol. Exposed SMB is extremely dangerous - prime target for ransomware and worms.",
        security_implications=[
            "EternalBlue and related RCE vulnerabilities",
            "Ransomware propagation (WannaCry, NotPetya)",
            "File share enumeration and data theft",
            "Credential capture via hash relaying",
            "Lateral movement within networks",
        ],
        common_attack_vectors=[
            "EternalBlue exploitation (MS17-010)",
            "SMB relay attacks",
            "Share enumeration and sensitive file access",
            "Brute force attacks",
            "PsExec-style remote execution",
            "Null session enumeration",
        ],
        remediation_steps=[
            "NEVER expose SMB to internet",
            "Block ports 139, 445 at perimeter firewall",
            "Keep systems patched (EternalBlue, etc.)",
            "Disable SMBv1 completely",
            "Require SMB signing",
            "Use network segmentation",
            "Implement strong access controls on shares",
            "Monitor SMB traffic for anomalies",
        ],
        detection_tips=[
            "Alert on any SMB traffic from internet",
            "Monitor for exploitation attempts (IDS signatures)",
            "Watch for unusual share access patterns",
            "Track failed authentication attempts",
        ],
        references=[
            "https://attack.mitre.org/techniques/T1021/002/",
            "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-disable-smbv1-v2-v3",
        ],
        related_cves=["CVE-2017-0144 (EternalBlue)", "CVE-2020-0796 (SMBGhost)"],
        tools_for_testing=["smbclient", "smbmap", "CrackMapExec", "Nmap smb scripts"],
    ),

    21: ServiceGuidance(
        service_name="FTP",
        risk_level="medium",
        description="FTP is an unencrypted file transfer protocol. Credentials and data are transmitted in cleartext.",
        security_implications=[
            "Credentials transmitted in cleartext",
            "Anonymous access may expose sensitive files",
            "Brute force attacks",
            "File manipulation if write access exists",
            "Bounce attacks for port scanning",
        ],
        common_attack_vectors=[
            "Credential sniffing",
            "Anonymous login exploitation",
            "Brute force attacks",
            "Directory traversal vulnerabilities",
            "Webshell upload if connected to web root",
        ],
        remediation_steps=[
            "Replace FTP with SFTP or FTPS",
            "Disable anonymous access unless required",
            "Use strong passwords",
            "Implement IP-based access restrictions",
            "Chroot users to their directories",
            "Disable write access where not needed",
            "Regular security audits of uploaded content",
        ],
        detection_tips=[
            "Monitor for anonymous login attempts",
            "Alert on failed authentication attempts",
            "Watch for unusual file uploads",
            "Track large data transfers",
        ],
        references=[
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp",
        ],
        default_credentials=["anonymous:anonymous", "ftp:ftp", "admin:admin"],
        tools_for_testing=["ftp", "lftp", "Nmap ftp scripts", "Hydra"],
    ),

    # =========================================================================
    # CONTAINERS / ORCHESTRATION
    # =========================================================================
    2375: ServiceGuidance(
        service_name="Docker API (Unencrypted)",
        risk_level="critical",
        description="Docker API without TLS allows complete container and host control. This is one of the most critical exposures.",
        security_implications=[
            "Complete control over all containers",
            "Container escape to host system",
            "Cryptocurrency mining deployment",
            "Data theft from all containers",
            "Persistent backdoor installation",
            "Host filesystem access via volume mounts",
        ],
        common_attack_vectors=[
            "List containers: docker -H <ip>:2375 ps -a",
            "Pull and run malicious containers",
            "Mount host filesystem: docker run -v /:/host ...",
            "Read sensitive files from containers",
            "Deploy cryptocurrency miners",
            "Establish reverse shells",
        ],
        remediation_steps=[
            "NEVER expose Docker API to internet",
            "Use TLS with client certificate authentication",
            "Use Docker socket through SSH tunnel if remote access needed",
            "Implement Docker socket proxy with authorization",
            "Use container orchestration with RBAC (Kubernetes, Swarm)",
            "Enable Docker audit logging",
            "Use AppArmor/SELinux profiles",
        ],
        detection_tips=[
            "Alert on any external Docker API connections",
            "Monitor for unexpected container creation",
            "Watch for privileged containers",
            "Track volume mounts to sensitive paths",
        ],
        references=[
            "https://docs.docker.com/engine/security/protect-access/",
            "https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker",
        ],
        default_credentials=["No authentication by default"],
        tools_for_testing=["docker CLI", "curl", "Nmap docker scripts"],
    ),

    2376: ServiceGuidance(
        service_name="Docker API (TLS)",
        risk_level="high",
        description="Docker API with TLS. While encrypted, misconfigured certificates or leaked keys still pose significant risk.",
        security_implications=[
            "Same as unencrypted Docker API if certificates compromised",
            "Certificate validation bypass vulnerabilities",
            "Key theft enables complete Docker control",
        ],
        common_attack_vectors=[
            "Certificate theft or generation",
            "TLS downgrade attacks",
            "Same attacks as port 2375 if access gained",
        ],
        remediation_steps=[
            "Use strong certificates from trusted CA",
            "Implement proper certificate rotation",
            "Secure certificate storage",
            "Use certificate pinning where possible",
            "Same mitigations as port 2375",
        ],
        detection_tips=[
            "Monitor certificate usage",
            "Alert on connections with unexpected certificates",
            "Same monitoring as port 2375",
        ],
        references=[
            "https://docs.docker.com/engine/security/protect-access/",
        ],
        tools_for_testing=["docker CLI with --tls flags", "curl with certificates"],
    ),

    6443: ServiceGuidance(
        service_name="Kubernetes API Server",
        risk_level="critical",
        description="Kubernetes API server controls the entire cluster. Exposed or misconfigured API allows complete cluster compromise.",
        security_implications=[
            "Complete cluster control",
            "Deploy malicious workloads",
            "Access secrets (credentials, API keys)",
            "Pod escape to nodes",
            "Lateral movement across cluster",
            "Data theft from all applications",
        ],
        common_attack_vectors=[
            "Unauthenticated API access",
            "Anonymous authentication enabled",
            "Token theft and reuse",
            "RBAC misconfiguration exploitation",
            "etcd access for secrets",
            "Pod privilege escalation",
        ],
        remediation_steps=[
            "Never expose API server to internet",
            "Use private API endpoints (cloud providers)",
            "Disable anonymous authentication",
            "Implement proper RBAC",
            "Enable audit logging",
            "Use network policies",
            "Rotate credentials regularly",
            "Enable Pod Security Standards",
        ],
        detection_tips=[
            "Monitor API server audit logs",
            "Alert on anonymous or system:* access",
            "Watch for privileged pod creation",
            "Track secrets access patterns",
        ],
        references=[
            "https://kubernetes.io/docs/concepts/security/",
            "https://attack.mitre.org/matrices/enterprise/cloud/kubernetes/",
        ],
        tools_for_testing=["kubectl", "kube-hunter", "kubeaudit"],
    ),

    2379: ServiceGuidance(
        service_name="etcd",
        risk_level="critical",
        description="etcd is Kubernetes' key-value store containing all cluster data including secrets. Exposed etcd is catastrophic.",
        security_implications=[
            "Access to all Kubernetes secrets (in plaintext without encryption at rest)",
            "Cluster configuration theft",
            "Ability to modify cluster state",
            "Service account token theft",
            "Complete cluster compromise",
        ],
        common_attack_vectors=[
            "Direct key enumeration: etcdctl get / --prefix",
            "Secrets extraction",
            "Cluster state modification",
            "Denial of service",
        ],
        remediation_steps=[
            "NEVER expose etcd externally",
            "Use TLS for client and peer communication",
            "Enable client certificate authentication",
            "Enable encryption at rest for secrets",
            "Restrict etcd access to API server only",
            "Regular etcd backups",
        ],
        detection_tips=[
            "Alert on any external etcd connections",
            "Monitor for unusual key access patterns",
            "Watch for bulk read operations",
        ],
        references=[
            "https://etcd.io/docs/v3.5/op-guide/security/",
            "https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/",
        ],
        default_credentials=["No authentication by default"],
        tools_for_testing=["etcdctl", "curl"],
    ),

    # =========================================================================
    # CI/CD
    # =========================================================================
    8080: ServiceGuidance(
        service_name="Jenkins",
        risk_level="high",
        description="Jenkins is a CI/CD automation server. Exposed Jenkins can lead to code execution and supply chain attacks.",
        security_implications=[
            "Groovy script execution (full system access)",
            "Credential theft from credential store",
            "Source code access and modification",
            "Supply chain attacks via build manipulation",
            "Lateral movement via build agents",
        ],
        common_attack_vectors=[
            "Script console for code execution (/script)",
            "Credential dumping",
            "Build job manipulation",
            "Plugin exploitation",
            "Default/weak credentials",
        ],
        remediation_steps=[
            "Enable authentication (disable anonymous access)",
            "Use strong passwords and consider SSO/LDAP",
            "Implement role-based authorization",
            "Restrict script console access",
            "Keep Jenkins and plugins updated",
            "Use credentials binding, not plaintext",
            "Audit build configurations",
            "Network segment build infrastructure",
        ],
        detection_tips=[
            "Monitor script console access",
            "Alert on new admin user creation",
            "Watch for build configuration changes",
            "Track credential access",
        ],
        references=[
            "https://www.jenkins.io/doc/book/security/",
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/jenkins",
        ],
        default_credentials=["admin:admin", "jenkins:jenkins"],
        tools_for_testing=["jenkins-cli", "Nmap http scripts"],
    ),

    # =========================================================================
    # MONITORING
    # =========================================================================
    9090: ServiceGuidance(
        service_name="Prometheus",
        risk_level="medium",
        description="Prometheus is a monitoring system. Exposed Prometheus reveals internal infrastructure and metrics.",
        security_implications=[
            "Internal infrastructure mapping",
            "Service discovery information exposure",
            "Metric data revealing business information",
            "Target discovery for further attacks",
            "Alert rule exposure showing security controls",
        ],
        common_attack_vectors=[
            "Target enumeration via /targets",
            "Configuration exposure via /config",
            "Metric scraping for sensitive data",
            "Alert rule analysis",
        ],
        remediation_steps=[
            "Enable authentication (reverse proxy or --web.enable-admin-api)",
            "Use TLS for Prometheus endpoints",
            "Restrict access to internal networks",
            "Review exposed metrics for sensitive data",
            "Use network segmentation",
        ],
        detection_tips=[
            "Monitor for external access to /api/v1 endpoints",
            "Alert on config or target enumeration",
        ],
        references=[
            "https://prometheus.io/docs/prometheus/latest/security/",
        ],
        default_credentials=["No authentication by default"],
        tools_for_testing=["curl", "promtool"],
    ),

    5601: ServiceGuidance(
        service_name="Kibana",
        risk_level="medium",
        description="Kibana is the visualization layer for Elasticsearch. Exposed Kibana reveals logged data and can lead to code execution.",
        security_implications=[
            "Access to all Elasticsearch data via visualization",
            "Log data exposure (may contain credentials, PII)",
            "Server-side request forgery vulnerabilities",
            "Code execution via scripting (older versions)",
        ],
        common_attack_vectors=[
            "Dashboard enumeration for sensitive data",
            "Dev Tools console for Elasticsearch queries",
            "SSRF exploitation",
            "Prototype pollution (older versions)",
        ],
        remediation_steps=[
            "Enable X-Pack Security authentication",
            "Use TLS",
            "Implement role-based access control",
            "Keep Kibana updated",
            "Restrict access to internal networks",
            "Review dashboards for sensitive data exposure",
        ],
        detection_tips=[
            "Monitor login attempts",
            "Alert on Dev Tools usage",
            "Watch for unusual query patterns",
        ],
        references=[
            "https://www.elastic.co/guide/en/kibana/current/kibana-security.html",
        ],
        default_credentials=["No authentication by default (without X-Pack)"],
        tools_for_testing=["curl", "Browser"],
    ),

    3000: ServiceGuidance(
        service_name="Grafana",
        risk_level="medium",
        description="Grafana is a monitoring visualization platform. Exposed Grafana can reveal sensitive metrics and enable further attacks.",
        security_implications=[
            "Internal infrastructure visibility",
            "Data source credential exposure",
            "SSRF via data source proxying",
            "Sensitive metric data exposure",
        ],
        common_attack_vectors=[
            "Default credential exploitation",
            "Data source enumeration",
            "SSRF via proxy endpoints",
            "Path traversal (older versions)",
        ],
        remediation_steps=[
            "Change default admin password immediately",
            "Disable user registration",
            "Use OAuth/LDAP for authentication",
            "Restrict anonymous access",
            "Keep Grafana updated",
            "Review data source permissions",
            "Use network segmentation",
        ],
        detection_tips=[
            "Monitor login attempts",
            "Alert on data source modifications",
            "Watch for unusual API requests",
        ],
        references=[
            "https://grafana.com/docs/grafana/latest/administration/security/",
        ],
        default_credentials=["admin:admin"],
        related_cves=["CVE-2021-43798 (Path traversal)"],
        tools_for_testing=["curl", "Browser"],
    ),
}

# Port to common service name mapping
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker API",
    2376: "Docker API (TLS)",
    2379: "etcd",
    3000: "Grafana/Node",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "RabbitMQ",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    8080: "HTTP Proxy/Jenkins",
    8443: "HTTPS Alt",
    9000: "Portainer",
    9042: "Cassandra",
    9090: "Prometheus",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    15672: "RabbitMQ Mgmt",
    27017: "MongoDB",
}


def get_service_guidance(port: int) -> Optional[ServiceGuidance]:
    """Get security guidance for a specific port."""
    return SERVICE_GUIDANCE.get(port)


def get_service_name(port: int) -> str:
    """Get common service name for a port."""
    return PORT_SERVICE_MAP.get(port, f"Port {port}")


def get_risk_color(risk_level: str) -> str:
    """Get CSS color class for risk level."""
    colors = {
        "critical": "tag-critical",
        "high": "tag-high",
        "medium": "tag-medium",
        "low": "tag-low",
        "info": "tag-info",
    }
    return colors.get(risk_level, "tag-info")


def format_guidance_html(guidance: ServiceGuidance) -> str:
    """Format service guidance as HTML for reports."""
    html = f"""
    <div class="service-guidance">
        <h4>{guidance.service_name} Security Guidance</h4>
        <p class="guidance-desc">{guidance.description}</p>

        <div class="guidance-section">
            <h5>Security Implications</h5>
            <ul>
                {''.join(f'<li>{imp}</li>' for imp in guidance.security_implications)}
            </ul>
        </div>

        <div class="guidance-section">
            <h5>Common Attack Vectors</h5>
            <ul>
                {''.join(f'<li><code>{vec}</code></li>' for vec in guidance.common_attack_vectors)}
            </ul>
        </div>

        <div class="guidance-section">
            <h5>Remediation Steps</h5>
            <ol>
                {''.join(f'<li>{step}</li>' for step in guidance.remediation_steps)}
            </ol>
        </div>

        {f'''<div class="guidance-section">
            <h5>Default Credentials to Check</h5>
            <ul>
                {''.join(f'<li><code>{cred}</code></li>' for cred in guidance.default_credentials)}
            </ul>
        </div>''' if guidance.default_credentials else ''}

        {f'''<div class="guidance-section">
            <h5>Related CVEs</h5>
            <ul>
                {''.join(f'<li>{cve}</li>' for cve in guidance.related_cves)}
            </ul>
        </div>''' if guidance.related_cves else ''}

        <div class="guidance-section">
            <h5>References</h5>
            <ul>
                {''.join(f'<li><a href="{ref}" target="_blank">{ref}</a></li>' for ref in guidance.references)}
            </ul>
        </div>
    </div>
    """
    return html
