"""Subconjunto de MITRE ATT&CK usado por las detecciones."""

TACTICS = {
    "reconnaissance": ("TA0043", "Reconocimiento"),
    "initial-access": ("TA0001", "Acceso inicial"),
    "execution": ("TA0002", "Ejecución"),
    "persistence": ("TA0003", "Persistencia"),
    "privilege-escalation": ("TA0004", "Escalada de privilegios"),
    "defense-evasion": ("TA0005", "Evasión de defensas"),
    "credential-access": ("TA0006", "Acceso a credenciales"),
    "discovery": ("TA0007", "Descubrimiento"),
    "lateral-movement": ("TA0008", "Movimiento lateral"),
    "collection": ("TA0009", "Recolección"),
    "command-and-control": ("TA0011", "Comando y control"),
    "exfiltration": ("TA0010", "Exfiltración"),
    "impact": ("TA0040", "Impacto"),
}

# Orden de la cadena de ataque (para valorar progresión en incidentes)
KILL_CHAIN = list(TACTICS)

TECHNIQUES = {
    "T1003": "OS Credential Dumping", "T1003.008": "/etc/passwd and /etc/shadow",
    "T1014": "Rootkit", "T1021.004": "Remote Services: SSH", "T1027": "Obfuscated Files",
    "T1027.002": "Software Packing", "T1036": "Masquerading", "T1036.005": "Match Legitimate Name",
    "T1037": "Boot or Logon Initialization Scripts", "T1040": "Network Sniffing",
    "T1046": "Network Service Discovery", "T1048": "Exfiltration Over Alternative Protocol",
    "T1053.003": "Scheduled Task: Cron", "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell",
    "T1059.004": "Unix Shell", "T1059.006": "Python", "T1068": "Exploitation for Privilege Escalation",
    "T1070.002": "Clear Linux or Mac System Logs", "T1070.003": "Clear Command History",
    "T1070.004": "File Deletion", "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts", "T1082": "System Information Discovery",
    "T1087": "Account Discovery", "T1098": "Account Manipulation",
    "T1098.004": "SSH Authorized Keys", "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force", "T1110.001": "Password Guessing", "T1110.003": "Password Spraying",
    "T1136.001": "Create Local Account", "T1140": "Deobfuscate/Decode Files",
    "T1190": "Exploit Public-Facing Application", "T1200": "Hardware Additions",
    "T1222.002": "Linux File Permissions Modification", "T1486": "Data Encrypted for Impact",
    "T1485": "Data Destruction", "T1489": "Service Stop", "T1490": "Inhibit System Recovery",
    "T1496": "Resource Hijacking", "T1505.003": "Web Shell", "T1543.002": "Systemd Service",
    "T1546.004": "Unix Shell Configuration Modification", "T1547.006": "Kernel Modules",
    "T1548.001": "Setuid and Setgid", "T1548.003": "Sudo and Sudo Caching",
    "T1552.001": "Credentials In Files", "T1552.004": "Private Keys",
    "T1556.003": "Pluggable Authentication Modules", "T1562.001": "Disable or Modify Tools",
    "T1562.004": "Disable or Modify System Firewall", "T1564.001": "Hidden Files and Directories",
    "T1571": "Non-Standard Port", "T1573": "Encrypted Channel", "T1574.006": "Dynamic Linker Hijacking",
    "T1595": "Active Scanning", "T1620": "Reflective Code Loading", "T1091": "Replication Through Removable Media",
    "T1052": "Exfiltration Over Physical Medium", "T1219": "Remote Access Software",
    "T1204": "User Execution", "T1566": "Phishing", "T1003.007": "Proc Filesystem",
    "T1057": "Process Discovery", "T1018": "Remote System Discovery", "T1560": "Archive Collected Data",
    "T1567": "Exfiltration Over Web Service", "T1569": "System Services", "T1611": "Escape to Host",
    "T1649": "Steal or Forge Authentication Certificates", "T1090": "Proxy",
    "T1572": "Protocol Tunneling", "T1095": "Non-Application Layer Protocol",
    "T1218": "System Binary Proxy Execution", "T1547.001": "Registry Run Keys / Startup Folder",
    "T1499": "Endpoint Denial of Service", "T1565.001": "Stored Data Manipulation",
    "T1078.003": "Local Accounts", "T1021": "Remote Services", "T1531": "Account Access Removal",
    "T1546": "Event Triggered Execution", "T1555.003": "Credentials from Web Browsers",
}


def tactic_label(tactic: str) -> str:
    tid, name = TACTICS.get(tactic, ("", tactic))
    return f"{tid} {name}".strip()
