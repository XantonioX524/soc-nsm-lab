# Laboratorio de NSM y Detección de Amenazas (SOC / Blue Team)

Este repositorio contiene la infraestructura automatizada (Infra-as-Code) para desplegar un entorno completo de monitorización de seguridad de redes (NSM), detección de intrusos (IDS) y recolección de logs centralizada (SIEM).

Está diseñado específicamente para entrenar y validar casos de uso de **Blue Team**, análisis de tráfico de red, desarrollo de reglas de detección y simulaciones de ataque (Purple Teaming).

## Arquitectura del Laboratorio

El entorno está compuesto por 4 máquinas virtuales segmentadas en una red interna, simulando un entorno corporativo monitorizado.
![[infrastructure.png]]
### Matriz de Direccionamiento IP
| Rol                  | SO / Tecnología        | Dirección IP     | Descripción                                                         |
| :------------------- | :--------------------- | :--------------- | :------------------------------------------------------------------ |
| **Atacante**         | Kali Linux             | `192.168.10.50`  | Máquina ofensiva (Red Team).                                        |
| **Sensor (IDS/NSM)** | Ubuntu Server          | `192.168.10.253` | Motor de captura pasiva (Snort + Zeek) y envío de telemetría.       |
| **SIEM**             | Ubuntu Server          | `192.168.10.250` | Servidor Splunk Enterprise (Receptor y panel de análisis).          |
| **Víctima**          | Ubuntu Server (Docker) | `192.168.10.100` | Entorno de contenedores con vulnerabilidades y servicios expuestos. |

---

## Componentes y Servicios Desplegados

### 1. SIEM (Splunk Enterprise)
Implementado mediante el script `install_siem.sh`. Actúa como el cerebro del SOC, ingiriendo alertas y telemetría de red.
* **Puerto web:** `8000` (Interfaz de analista)
* **Puerto de ingesta:** `9997` (Escucha para Universal Forwarder)

### 2. Sonda NSM (Sensor)
Implementado mediante el script `install_sensor.sh`. Realiza la inspección profunda de paquetes (DPI):
* **Snort:** Configurado con reglas a medida para capa de aplicación (L7) detectando inyecciones, XSS, ejecución de comandos y subida de WebShells.
* **Zeek:** Genera metadatos estructurados en JSON (conexiones, DNS, HTTP, SSH, FTP) y extrae *payloads* HTTP POST para análisis forense avanzado.
* **Splunk Universal Forwarder:** Envía automáticamente los eventos en tiempo real al SIEM.

### 3. Entorno Víctima (Docker Compose)
Despliega dos contenedores (`victima_web` y `victima_servicios`) con las siguientes superficies de ataque:
* **Frontend Web (Puerto 8081):** Portal de intranet simulado con utilidades de red (CMD Injection), buscador (XSS) y sistema de subida de recursos (Unrestricted File Upload).
* **Backend Web (Puerto 8082):** Directorio de empleados conectado a SQLite vulnerable a Inyecciones SQL (SQLi).
* **Servicios Administrativos:** 
  * SSH en puerto no estándar (`2222`)
  * FTP en puerto no estándar (`2121`)

---

## Vectores de Ataque y Casos de Uso Soportados

Este laboratorio está preparado para ejecutar y detectar las siguientes técnicas de ataque (Mapeadas con alertas de Snort y logs de Zeek):

- **Fuerza Bruta y Ataques de Diccionario:** SSH (`2222`) y FTP (`2121`).
- **Fuzzing y Descubrimiento de Directorios:** Visibilidad de peticiones anómalas (Gobuster/DirBuster).
- **Ejecución Remota de Comandos (RCE):** A través del servicio de ping en PHP.
- **Cross-Site Scripting (XSS):** Reflejado en el buscador de la wiki interna.
- **Subida de WebShells:** Evasión de controles en el portal de marketing para obtener persistencia.
- **Inyección SQL (SQLi):** Extracción de contraseñas de la base de datos `db.sqlite`.
- **Local File Inclusion / Path Traversal:** Acceso a archivos `/etc/passwd` y lectura de confidenciales.

---

## Despliegue (Quick Start)

### Paso 1: Levantar el nodo SIEM
En la máquina de Splunk (192.168.10.250), ejecutar con permisos de superusuario:
```bash
sudo chmod +x install_siem.sh
sudo ./install_siem.sh
```

### Paso 2: Levantar el nodo Sensor (IDS)

En la máquina de monitorización (192.168.10.253), ejecutar con permisos de superusuario:

```Bash
sudo chmod +x install_sensor.sh
sudo ./install_sensor.sh
```

### Paso 3: Levantar el entorno Víctima

En la máquina vulnerable (192.168.10.100), tener instalado Docker y ejecutar:

```Bash
sudo docker-compose up -d
```

---

## Credenciales del Laboratorio (Para pruebas "White Box")

**Splunk Enterprise (SIEM):**

- Usuario: `admin`
    
- Contraseña: `admin123`
    

**Servicio SSH (Puerto 2222):**

- `root` : `toor`
    
- `admin` : `admin123`
    
- `c.rodriguez` : `supersecreto`
    

**Servicio FTP (Puerto 2121):**

- `ftpuser` : `ftp123`
    
- `marketinguser` : `marketing123`
    

**Usuarios de la BD (SQLite - Puerto 8082):**

- Contiene credenciales en texto plano para los usuarios: `admin`, `j.doe`, `m.lopez`, `a.garcia`, `p.sanchez` y `c.rodriguez`.
    

---

## ⚠️ Disclaimer

> **Uso Ético:** Este entorno ha sido diseñado única y exclusivamente para propósitos educativos y de investigación en ciberseguridad. No despliegues estos contenedores en infraestructuras expuestas a Internet sin protecciones adicionales, ya que contienen vulnerabilidades críticas intencionadas.

***