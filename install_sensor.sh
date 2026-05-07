#!/bin/bash
# =====================================================================================
# Descripción: Despliegue automatizado de sonda NSM (Network Security Monitoring).
# Componentes: Snort (IDS basado en firmas), Zeek (Análisis de tráfico) y Splunk Universal Forwarder.
# Propósito: Automatizar la provisión de un IDS para entornos de laboratorio/SOC.
# =====================================================================================

# -------------------------------------------------------------------------------------
# VARIABLES DE ENTORNO Y CONFIGURACIÓN BASE
# -------------------------------------------------------------------------------------
# Dirección IP del servidor Splunk (SIEM / Indexer) receptor de telemetría
IP_SIEM="192.168.10.250"

# Detección dinámica de la interfaz de red principal activa (basado en la ruta por defecto)
INTERFAZ_RED=$(ip route | awk '/default/ {print $5}' | head -n1)
if [ -z "$INTERFAZ_RED" ]; then
    # Fallback de seguridad en caso de fallo en la detección dinámica del SO
    INTERFAZ_RED="ens33" 
fi

echo "======================================================================="
echo "[*] Interfaz de captura asignada: $INTERFAZ_RED"
echo "======================================================================="

# -------------------------------------------------------------------------------------
# FASE 1: ACTUALIZACIÓN DE SISTEMA E INSTALACIÓN DE DEPENDENCIAS
# -------------------------------------------------------------------------------------
echo "[*] [1/5] Resolviendo dependencias base del sistema operativo..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y wget curl net-tools gnupg lsb-release ca-certificates python3-websockets -qq

echo "[*] Añadiendo repositorio oficial y claves GPG para el motor Zeek..."
UBUNTU_VERSION=$(lsb_release -rs)
curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VERSION}/Release.key" | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VERSION}/ /" | tee /etc/apt/sources.list.d/security_zeek.list
apt-get update -qq

# -------------------------------------------------------------------------------------
# FASE 2: DESPLIEGUE DE MOTORES DE DETECCIÓN (IDS Y NSM)
# -------------------------------------------------------------------------------------
echo "[*] [2/5] Instalando servicios principales: Snort y Zeek..."
# Configuración desatendida (debconf) para evitar prompts interactivos que bloqueen el script
echo "snort snort/startup boolean false" | debconf-set-selections
echo "snort snort/address_range string 192.168.10.0/24" | debconf-set-selections
echo "snort snort/interface string $INTERFAZ_RED" | debconf-set-selections
echo "zeek zeek/interfaces string $INTERFAZ_RED" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y snort zeek -qq

# -------------------------------------------------------------------------------------
# FASE 3: IMPLEMENTACIÓN DEL CONJUNTO DE REGLAS Y FIRMAS (SNORT)
# -------------------------------------------------------------------------------------
echo "[*] [3/5] Aplicando firmas de detección en Snort (Capa de Aplicación y Servicios)..."
cat << 'EOF' > /etc/snort/rules/local.rules
# --- VECTORES DE ATAQUE WEB (Capa 7) ---
# Detección de intentos de inyección SQL (SQLi)
alert tcp any any -> any any (msg:"[ALERTA-WEB] Posible inyeccion SQL"; flow:established,to_server; pcre:"/(%27|\x27)(%20|\+|\s)*(OR|AND|UNION|ORDER(%20|\+|\s)+BY|SELECT|INSERT|UPDATE|DROP)/i"; sid:1000001; rev:1;)
# Detección de Cross-Site Scripting (XSS) en múltiples formatos y codificaciones
alert tcp any any -> any any (msg:"[ALERTA-WEB] XSS - script tag raw"; flow:established,to_server; content:"<script>"; nocase; sid:1000002; rev:1;)
alert tcp any any -> any any (msg:"[ALERTA-WEB] XSS - script tag encoded"; flow:established,to_server; content:"%3Cscript"; nocase; sid:1000003; rev:1;)
alert tcp any any -> any any (msg:"[ALERTA-WEB] XSS - event handler"; flow:established,to_server; pcre:"/(onerror|onload|onclick|onmouseover)=/i"; sid:1000004; rev:1;)
alert tcp any any -> any any (msg:"[ALERTA-WEB] XSS - javascript protocol"; flow:established,to_server; content:"javascript:"; nocase; sid:1000005; rev:1;)
# Detección de Directory Traversal y subida de archivos maliciosos (WebShells)
alert tcp any any -> any any (msg:"[ALERTA-WEB] Intento de Path Traversal"; flow:established,to_server; pcre:"/(\.\.\/|\.\.%2f|%2e%2e%2f)/i"; sid:1000013; rev:1;)
alert tcp any any -> any any (msg:"[ALERTA-WEB] Subida de WebShell"; flow:established,to_server; pcre:"/filename=(\x22|\x27)?.*\.(php|phtml|phar)/i"; sid:1000014; rev:1;)
alert tcp any any -> any any (msg:"[INFO-WEB] Subida de archivo detectada"; flow:established,to_server; content:"form-data|3B|"; nocase; content:"filename|3D|"; distance:0; nocase; sid:1000016; rev:4;)

# --- VECTORES DE ATAQUE A SERVICIOS INTERNOS (RCE y Comandos de Sistema) ---
# Detección de ejecución de comandos del sistema operativo (Reconocimiento y Exfiltración)
alert tcp any any -> any any (msg:"[ALERTA-SERVICIOS] CMD - reconocimiento sistema"; flow:established,to_server; pcre:"/(whoami|uname|id)/i"; sid:1000008; rev:1;)
alert tcp any any -> any any (msg:"[ALERTA-SERVICIOS] CMD - cat ruta raw"; flow:established,to_server; content:"cat /etc"; nocase; sid:1000009; rev:1;)
alert tcp any any -> any any (msg:"[ALERTA-SERVICIOS] CMD - cat ruta encoded"; flow:established,to_server; pcre:"/cat(%20|\+).*?%2Fetc/i"; sid:1000010; rev:1;)
alert tcp any any -> any any (msg:"[ALERTA-SERVICIOS] CMD - separador encoded con comando"; flow:established,to_server; pcre:"/(%3b|%7c|%26)(%20|\+|\s)*(whoami|id|ls|cat)/i"; sid:1000011; rev:1;)
alert tcp any any -> any any (msg:"[ALERTA-SERVICIOS] CMD - separador raw con comando"; flow:established,to_server; pcre:"/(\x3b|\x7c|\x26)(%20|\+|\s)*(whoami|id|ls|cat)/i"; sid:1000012; rev:1;)
# Detección de interacción web para ejecución de código remoto (RCE)
alert tcp any any -> any any (msg:"[ALERTA-SERVICIOS] Interaccion WebShell RCE"; flow:established,to_server; pcre:"/(\?|&)(cmd|exec|system|eval)=/i"; sid:1000015; rev:1;)
EOF

# Reinicio del demonio para cargar la nueva configuración de firmas en memoria
systemctl restart snort

# -------------------------------------------------------------------------------------
# FASE 4: CONFIGURACIÓN AVANZADA DE TELEMETRÍA (ZEEK)
# -------------------------------------------------------------------------------------
echo "[*] [4/5] Estructurando salida de logs (JSON) y extracción de payloads HTTP en Zeek..."

# Vinculación explícita de la interfaz de red detectada al archivo de configuración
sudo sed -i "s/^interface=.*/interface=$INTERFAZ_RED/" /opt/zeek/etc/node.cfg

# Política personalizada para el enriquecimiento de la telemetría (Scripts Base):
# Habilita salida estandarizada en JSON y extrae el cuerpo de peticiones POST limitando el tamaño.
cat << 'EOF' > /opt/zeek/share/zeek/site/local.zeek
@load tuning/json-logs
export { redef record HTTP::Info += { post_body: string &log &optional; }; }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
    if ( is_orig && c?$http && c$http?$method && c$http$method == "POST" ) {
        if ( ! c$http?$post_body ) { c$http$post_body = ""; }
        if ( |c$http$post_body| < 2000 ) { c$http$post_body = string_cat(c$http$post_body, data); }
    }
}
EOF

echo "[*] Compilando configuración y desplegando motor de Zeek..."
/opt/zeek/bin/zeekctl deploy

# -------------------------------------------------------------------------------------
# FASE 5: INTEGRACIÓN CON SIEM (SPLUNK UNIVERSAL FORWARDER)
# -------------------------------------------------------------------------------------
echo "[*] [5/5] Obteniendo e instalando Agente Universal Forwarder de Splunk..."
wget --user-agent="Mozilla/5.0" -O splunkfwd.deb "https://download.splunk.com/products/universalforwarder/releases/9.4.3/linux/splunkforwarder-9.4.3-237ebbd22314-linux-amd64.deb" -q --show-progress

# Verificación de integridad básica de la descarga (Tamaño esperado > 10MB)
FILE_SIZE_FW=$(stat -c%s "splunkfwd.deb" 2>/dev/null)
if [ -n "$FILE_SIZE_FW" ] && [ "$FILE_SIZE_FW" -gt 10000000 ]; then
    dpkg -i splunkfwd.deb
    
    # Auto-generación de credenciales administrativas iniciales (evita prompts)
    cat << 'EOF' > /opt/splunkforwarder/etc/system/local/user-seed.conf
[user_info]
USERNAME = admin
PASSWORD = admin123
EOF

    # Inicialización del servicio y aceptación desatendida del contrato (EULA)
    /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt
    
    # Configuración de reenvío hacia el nodo Indexador (SIEM)
    /opt/splunkforwarder/bin/splunk add forward-server $IP_SIEM:9997 -auth admin:admin123

    # Definición del pipeline de ingesta local (Alertas Snort + Metadatos Zeek)
    cat << 'EOF' > /opt/splunkforwarder/etc/system/local/inputs.conf
[default]
host = Sensor-IDS-NSM

[monitor:///var/log/snort/alert]
disabled = false
sourcetype = snort

[monitor:///opt/zeek/spool/zeek/*.log]
disabled = false
sourcetype = _json
EOF

    echo "[*] Aplicando configuración de persistencia del servicio de Forwarder..."
    /opt/splunkforwarder/bin/splunk restart
    /opt/splunkforwarder/bin/splunk enable boot-start -user root
    
    # Limpieza de paquetes de instalación para ahorro de espacio
    rm -f splunkfwd.deb
else
    echo "[-] CRÍTICO: Fallo en la integridad de la descarga del binario de Splunk. Abortando instalación del agente."
fi

echo "======================================================================="
echo "[+] PROVISIÓN COMPLETADA EXITOSAMENTE."
echo "[+] Servicios de monitorización (IDS/NSM) activos en la interfaz: $INTERFAZ_RED"
echo "======================================================================="
