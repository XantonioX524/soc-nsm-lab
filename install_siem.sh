#!/bin/bash
# =========================================================================
# Nombre: install_siem.sh
# Descripción: Instalación 100% automatizada de Splunk Enterprise
# =========================================================================

echo "======================================================"
echo "[*] INICIANDO DESPLIEGUE DEL SIEM (SPLUNK ENTERPRISE)"
echo "======================================================"

echo "[*] Instalando dependencias previas..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y wget curl net-tools ufw -qq

echo "[*] Descargando Splunk Enterprise directamente..."
wget --user-agent="Mozilla/5.0" -O splunk.deb "https://download.splunk.com/products/splunk/releases/9.4.3/linux/splunk-9.4.3-237ebbd22314-linux-amd64.deb" -q --show-progress

# Comprobar que se ha descargado un archivo real (cambiado a FILE_SIZE por la codificación)
FILE_SIZE=$(stat -c%s "splunk.deb" 2>/dev/null)
if [ -z "$FILE_SIZE" ] || [ "$FILE_SIZE" -lt 100000000 ]; then
    echo "[-] ERROR: La descarga falló o Splunk bloqueó la conexión."
    rm -f splunk.deb
    exit 1
fi

echo "[*] Instalando Splunk en el sistema..."
dpkg -i splunk.deb

echo "[*] Configurando credenciales por defecto (admin / admin123)"
mkdir -p /opt/splunk/etc/system/local/

cat << 'EOF' > /opt/splunk/etc/system/local/user-seed.conf
[user_info]
USERNAME = admin
PASSWORD = admin123
EOF

echo "[*] Desactivando límite de seguridad de 5000MB de espacio en disco..."
cat << 'EOF' > /opt/splunk/etc/system/local/server.conf
[diskUsage]
minFreeSpace = 50
EOF

echo "[*] Arrancando Splunk y aceptando licencia..."
/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt

echo "[*] Habilitando puerto de recepción de logs (9997) y configurando Firewall..."
/opt/splunk/bin/splunk enable listen 9997 -auth admin:admin123
ufw allow 9997/tcp > /dev/null 2>&1

echo "[*] Habilitando inicio automático..."
/opt/splunk/bin/splunk enable boot-start

echo "[*] Limpiando instaladores temporales..."
rm -f splunk.deb

echo "======================================================"
echo "[+] SIEM DESPLEGADO CON ÉXITO. Acceso en http://192.168.10.250:8000"
echo "======================================================"