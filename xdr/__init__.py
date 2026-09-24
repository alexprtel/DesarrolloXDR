"""SentinelXDR - plataforma XDR (Extended Detection & Response) ligera.

Componentes:
  * Agente de endpoint: sensores (procesos, red, ficheros, autenticación,
    persistencia, kernel/rootkits, dispositivos, cuentas, recursos, postura).
  * Motor de detección: reglas YAML, IOCs, firmas de malware, analítica de
    comportamiento y correlación con MITRE ATT&CK.
  * Respuesta: matar procesos, cuarentena, bloqueo de IPs, aislamiento de
    host, bloqueo de usuarios, recolección forense.
  * Servidor central: API REST, correlación multi-host y consola web.
"""

__version__ = "1.0.0"
