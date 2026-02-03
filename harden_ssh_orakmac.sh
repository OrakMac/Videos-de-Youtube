#!/bin/bash
# ============================================================
#  Orakmac | Ciberseguridad Defensiva
#  Script: SSH Hardening (Blue Team / SOC)
# ============================================================
#  ⚠️ ADVERTENCIA:
#  - Ejecutar como root
#  - Tener acceso por consola
#  - Tener llaves SSH configuradas
# ============================================================

clear

cat << "EOF"
============================================================
   ██████╗ ██████╗  █████╗ ██╗  ██╗███╗   ███╗ █████╗  ██████╗
  ██╔═══██╗██╔══██╗██╔══██╗██║ ██╔╝████╗ ████║██╔══██╗██╔════╝
  ██║   ██║██████╔╝███████║█████╔╝ ██╔████╔██║███████║██║     
  ██║   ██║██╔══██╗██╔══██║██╔═██╗ ██║╚██╔╝██║██╔══██║██║     
  ╚██████╔╝██║  ██║██║  ██║██║  ██╗██║ ╚═╝ ██║██║  ██║╚██████╗
   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝
============================================================
     SSH Hardening - Blue Team | Orakmac
============================================================

Este script:
- Hará backup de sshd_config
- Aplicará hardening recomendado (Lynis / Linux Audit)
- Validará la configuración
- Recargará el servicio SSH correcto

Presiona ENTER para continuar o CTRL+C para cancelar
EOF

read

set -e

CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak_$(date +%F_%H-%M-%S)"

echo "[*] Creando backup: $BACKUP"
cp "$CONFIG" "$BACKUP"

# ------------------------------------------------------------
# Función para aplicar configuración segura
# ------------------------------------------------------------
apply() {
  KEY="$1"
  VALUE="$2"

  if grep -qE "^${KEY}\s+" "$CONFIG"; then
    sed -i "s|^${KEY}\s\+.*|${KEY} ${VALUE}|" "$CONFIG"
  else
    echo "${KEY} ${VALUE}" >> "$CONFIG"
  fi
}

echo "[*] Aplicando hardening SSH..."

# === Autenticación ===
apply Protocol 2
apply PermitRootLogin no
apply PasswordAuthentication no
apply PermitEmptyPasswords no
apply PubkeyAuthentication yes
apply LoginGraceTime 30
apply MaxAuthTries 3

# === Control de sesión ===
apply ClientAliveInterval 300
apply ClientAliveCountMax 2
apply MaxSessions 2
apply TCPKeepAlive no

# === Forwarding / túneles ===
apply AllowTcpForwarding no
apply AllowAgentForwarding no
apply X11Forwarding no
apply PermitTunnel no
apply GatewayPorts no

# === Auditoría y visibilidad ===
apply LogLevel VERBOSE
apply UseDNS no
apply IgnoreRhosts yes
apply StrictModes yes
apply PrintLastLog yes
apply FingerprintHash sha256

# === Control de acceso ===
apply AllowGroups sshusers

# === Puerto SSH (AJUSTAR SEGÚN ENTORNO) ===
apply Port 2222

# ------------------------------------------------------------
# Validar configuración
# ------------------------------------------------------------
echo "[*] Validando configuración SSH..."
if ! sshd -t; then
  echo "[✖] Error en sshd_config. Restaurando backup."
  cp "$BACKUP" "$CONFIG"
  exit 1
fi

# ------------------------------------------------------------
# Detectar y recargar servicio SSH correcto
# ------------------------------------------------------------
echo "[*] Detectando servicio SSH..."

if systemctl list-unit-files | grep -q "^ssh.service"; then
    SSH_SERVICE="ssh"
elif systemctl list-unit-files | grep -q "^sshd.service"; then
    SSH_SERVICE="sshd"
else
    echo "[✖] No se pudo detectar el servicio SSH"
    exit 1
fi

echo "[*] Recargando servicio: $SSH_SERVICE"
systemctl reload "$SSH_SERVICE"

echo
echo "[✔] SSH HARDENING COMPLETADO CORRECTAMENTE"
echo "[🔵] Orakmac | Ciberseguridad Defensiva"
echo "[📁] Backup guardado en: $BACKUP"
