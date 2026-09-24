# SentinelXDR

Plataforma **XDR (Extended Detection & Response)** ligera, escrita en Python, para proteger
equipos Linux (con soporte parcial de Windows/macOS). Incluye agente de endpoint, motor de
detección, respuesta automática, correlación multi-equipo y consola web.

```
 ┌──────────────── Endpoint (agente) ─────────────────┐        ┌────────── Servidor XDR ──────────┐
 │ Sensores ─► Motor de detección ─► Respuesta auto.  │ HTTPS  │ Ingesta · Correlación · Incidentes│
 │ procesos, red, ficheros, auth,   reglas · IOCs ·   │ ─────► │ Cola de comandos · Inteligencia   │
 │ persistencia, kernel, USB,       firmas · UEBA     │ ◄───── │ API REST · Consola web · SIEM     │
 │ cuentas, recursos, postura                          │ órdenes│                                   │
 └────────────────────────────────────────────────────┘        └───────────────────────────────────┘
```

## Qué protege

| Área | Sensor | Qué detecta (ejemplos) |
|---|---|---|
| **Procesos** | `process` (netlink en tiempo real + sondeo) | reverse shells, `curl \| sh`, criptomineros, binarios en `/tmp`, fileless/memfd, `LD_PRELOAD`, suplantación de `kworker`, webshell que lanza shell, volcado de credenciales, borrado de logs, desactivación de defensas, escape de contenedores, LOLBins de Windows, borrado de *shadow copies* |
| **Red** | `network` | puertos C2, pools de minería, *bind shells*, beaconing periódico, escaneos entrantes/salientes, movimiento lateral, Tor, SMTP anómalo, modo promiscuo, exfiltración por volumen (z-score) |
| **Integridad de ficheros** | `fim` | modificación de binarios del sistema, nuevos SUID, ficheros escribibles por todos |
| **Malware** | `malware_scan` + escáner | firmas estilo YARA (EICAR, webshells PHP/JSP/ASPX, reverse shells, XMRig, Mimikatz, Mirai, Cobalt Strike, rootkits, notas de rescate, stealers), IOCs de hash, heurística de empaquetado |
| **Ransomware** | `ransomware` | cifrado masivo por entropía, extensiones de ransomware, renombrados, notas de rescate, borrado masivo y **ficheros canario** |
| **Identidad** | `auth`, `accounts` | fuerza bruta, *password spraying*, login tras fuerza bruta, login desde origen nuevo (UEBA), sudo denegado, cuentas UID 0, alta en grupos privilegiados, contraseñas vacías |
| **Persistencia** | `persistence` | cron/at, systemd, init/rc.local, perfiles de shell, `authorized_keys`, `ld.so.preload`, sudoers, PAM, autostart, udev, hooks de APT, módulos de arranque, claves Run de Windows |
| **Kernel / rootkits** | `kernel` | carga de módulos, rootkits conocidos, **procesos ocultos** (técnica *unhide*), kernel contaminado |
| **Dispositivos** | `devices` | USB de almacenamiento, posibles BadUSB (HID + almacenamiento), montajes extraíbles |
| **Recursos** | `resources` | CPU sostenida (criptominería), disco lleno |
| **Postura** | `posture` | 25 controles de hardening tipo CIS (SSH, cortafuegos, servicios expuestos, sysctl, SUID peligrosos, sudoers, permisos…) con puntuación y remediación |

Todas las detecciones se mapean a **MITRE ATT&CK** (80 reglas, ~70 técnicas).

## Respuesta

Automática (a partir de la severidad configurada) o manual desde la consola:
matar/suspender procesos, **cuarentena** reversible, bloqueo de IPs (iptables/netsh),
**aislamiento de red** del equipo (solo queda el canal con el servidor), bloqueo de usuarios y
cierre de sesiones, contención de ransomware (termina el proceso que cifra en los directorios
afectados) y **recolección forense** (procesos, conexiones, sesiones, módulos, cron…).

Salvaguardas: modo `dry_run`, lista de procesos protegidos, lista de IPs que nunca se bloquean,
el aislamiento automático es *opt-in*, y la cuarentena **nunca** mueve binarios ni ficheros
críticos del sistema operativo (`/usr`, `/bin`, `/lib`, `/etc/passwd`, PAM…).

## Correlación e incidentes

Las alertas se agrupan en **incidentes** por equipo y por entidades compartidas (IP, hash,
usuario) entre equipos. Un incidente que abarca ≥3 tácticas genera *Ataque multi-etapa*
(crítico); la misma entidad en varios equipos genera *Actividad relacionada en varios equipos*.

## Puesta en marcha

Requisitos: Python ≥ 3.10, `psutil`, `PyYAML`. Ejecutar como **root** para visibilidad y
respuesta completas.

```bash
pip install .                      # o: pip install -r requirements.txt
sentinel-xdr init                  # genera config/xdr.yaml con token y clave aleatorios
sudo sentinel-xdr -c config/xdr.yaml run    # servidor + consola + agente local
# Consola: http://127.0.0.1:8443  (token = server.admin_token)
```

Despliegue en varios equipos:

```bash
# Servidor central (exponer con TLS: server.tls_cert / server.tls_key)
sentinel-xdr -c /etc/sentinel-xdr/xdr.yaml server --host 0.0.0.0
# Cada endpoint
sudo sentinel-xdr agent --server https://xdr.midominio:8443 --enroll-key <CLAVE>
```

O con el instalador systemd: `sudo ./deploy/install.sh standalone|server|agent URL CLAVE`.

### Otros comandos

| Comando | Función |
|---|---|
| `sentinel-xdr scan RUTA... [--quarantine]` | antimalware bajo demanda |
| `sentinel-xdr posture [--json]` | auditoría de hardening |
| `sentinel-xdr rules` | valida y lista las reglas |
| `sentinel-xdr intel update` | descarga IOCs de abuse.ch (Feodo, MalwareBazaar, URLhaus) |
| `sentinel-xdr intel add --type ips --value 1.2.3.4` | añade un IOC |
| `sentinel-xdr simulate [--auth-log F] [--ransomware-dir D]` | simulación **inofensiva** de ataques para validar la detección |
| `sentinel-xdr simulate --cleanup` | limpia los artefactos de la simulación |
| `sentinel-xdr status` | resumen desde el servidor |

## Consola web

Resumen (riesgo, incidentes, alertas por severidad, tácticas), incidentes con cronología,
alertas con respuesta en un clic, *threat hunting* sobre la telemetría, endpoints (aislar,
forense, escanear), postura, matriz MITRE ATT&CK, inteligencia de amenazas y registro de
acciones. Sin dependencias externas, con CSP estricta y todo el contenido escapado.

## Integraciones

- **SIEM**: reenvío de alertas en formato CEF por syslog UDP (`integrations.syslog`).
- **Webhooks**: Slack/Teams/genérico (`integrations.webhook_url`).
- **API REST** (Bearer token): `/api/alerts`, `/api/incidents`, `/api/events`, `/api/agents`,
  `/api/commands`, `/api/posture`, `/api/iocs`, `/api/rules`, `/api/mitre`, `/api/overview`.

## Reglas propias

Añada ficheros YAML en un directorio y decláralo en `detection.extra_rules_dirs`:

```yaml
- id: CUSTOM-001
  title: Ejecución de binario desde /mnt
  severity: medium
  tactic: execution
  mitre: [T1204]
  category: process
  action: start
  condition:
    all:
      - {field: exe, startswith: /mnt/}
      - not: {field: username, equals: backup}
  threshold: {count: 3, window: 60, group_by: [exe]}   # opcional
  response: [kill_process]                             # opcional
```

Operadores: `equals`, `not_equals`, `contains`, `not_contains`, `startswith`, `endswith`, `regex`,
`not_regex`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `exists`, `is_true`, `is_false`,
`length_gt`; combinables con `all` / `any` / `not`.

## Estructura

```
xdr/
  collectors/   sensores (process, network, files, auth, persistence, system, posture)
  detection/    reglas, IOCs, firmas, comportamiento (UEBA), correlación, MITRE
  response/     acciones de respuesta y playbooks
  server/       núcleo del servidor, API HTTP, notificaciones, consola (static/)
  data/         reglas YAML, firmas, IOCs
  agent.py      orquestación del agente · cli.py  línea de comandos · simulate.py
tests/          pruebas unitarias y de integración (pytest)
deploy/         servicios systemd e instalador
```

## Limitaciones conocidas

- Sensores basados en sondeo + netlink (no eBPF/auditd): un proceso extremadamente breve o un
  fichero creado y borrado entre dos sondeos puede no observarse.
- El soporte de Windows/macOS se limita a procesos, red, recursos y parte de la persistencia y
  la respuesta.
- La UEBA es estadística y ligera; ajuste `learning_period`, umbrales y listas de permitidos
  a su entorno para reducir falsos positivos.
