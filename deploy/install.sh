#!/usr/bin/env bash
# Instalador de SentinelXDR para Linux (ejecutar como root desde la raíz del repositorio).
#   ./deploy/install.sh standalone            -> servidor + agente local (un solo equipo)
#   ./deploy/install.sh server                -> solo servidor central
#   ./deploy/install.sh agent URL CLAVE       -> agente que reporta a un servidor
set -euo pipefail
MODE="${1:-standalone}"
[[ $EUID -eq 0 ]] || { echo "Ejecute como root"; exit 1; }
python3 -m venv /opt/sentinel-xdr
/opt/sentinel-xdr/bin/pip install --upgrade pip >/dev/null
/opt/sentinel-xdr/bin/pip install . >/dev/null
ln -sf /opt/sentinel-xdr/bin/sentinel-xdr /usr/local/bin/sentinel-xdr
mkdir -p /etc/sentinel-xdr /var/log/sentinel-xdr /var/lib/sentinel-xdr
chmod 700 /var/lib/sentinel-xdr
[[ -f /etc/sentinel-xdr/xdr.yaml ]] || sentinel-xdr init -o /etc/sentinel-xdr/xdr.yaml
case "$MODE" in
  standalone)
    sed "s#-c /etc/sentinel-xdr/xdr.yaml --log-file /var/log/sentinel-xdr/agent.log agent#-c /etc/sentinel-xdr/xdr.yaml --log-file /var/log/sentinel-xdr/xdr.log run#" \
      deploy/sentinel-xdr-agent.service > /etc/systemd/system/sentinel-xdr.service
    systemctl daemon-reload && systemctl enable --now sentinel-xdr ;;
  server)
    cp deploy/sentinel-xdr-server.service /etc/systemd/system/
    systemctl daemon-reload && systemctl enable --now sentinel-xdr-server ;;
  agent)
    URL="${2:?URL del servidor}"; KEY="${3:?clave de enrolamiento}"
    python3 - "$URL" "$KEY" <<'PY'
import sys, yaml
p = "/etc/sentinel-xdr/xdr.yaml"
cfg = yaml.safe_load(open(p)) or {}
cfg.setdefault("agent", {}).update({"server_url": sys.argv[1], "enroll_key": sys.argv[2]})
yaml.safe_dump(cfg, open(p, "w"), sort_keys=False)
PY
    cp deploy/sentinel-xdr-agent.service /etc/systemd/system/
    systemctl daemon-reload && systemctl enable --now sentinel-xdr-agent ;;
  *) echo "Modo desconocido: $MODE"; exit 1 ;;
esac
echo "SentinelXDR instalado ($MODE). Configuración: /etc/sentinel-xdr/xdr.yaml"
