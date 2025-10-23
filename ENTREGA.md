#**ENTREGA — IoT Secure App (Laboratorio Local)**
##**Resumen de la práctica**

Esta práctica introduce conceptos esenciales de seguridad en IoT, de forma local y sin conexión.
El estudiante interactúa con simuladores de UART, MQTT, seguridad de firmware, firmas OTA y una bitácora encadenada tipo blockchain.
Los módulos (core/) emulan operaciones y amenazas comunes: credenciales por defecto, manipulación de mensajes, control de acceso y trazabilidad de eventos.

##**Pasos para ejecutar el laboratorio**

**1. Clonar o copiar el proyecto en tu máquina local.**

**2. Crear entorno virtual y activar:**

python3 -m venv .venv
source .venv/bin/activate

**3. Instalar dependencias:**

pip install -r requirements.txt

**4. Ejecutar la aplicación principal:**

streamlit run app.py

**5. (Opcional) Ejecutar pruebas automáticas:**

pytest -q


💡 El entorno es local-only: no se realizan llamadas de red, descargas externas ni uso de hardware real.

##**Qué evidencias entregar**
Incluye los siguientes archivos y/o capturas en tu entrega final:

**1. Captura del panel “Firmware y Contraseñas” mostrando:**
- Resultado de attack_default_creds.
- Ejecución de first_boot con contraseña nueva.
- Verificación de login correcta.
- Proceso OTA: firma, verificación y actualización de ota_version.

**2. Captura del panel “Blockchain y Seguridad” con:**
- Al menos dos lecturas registradas en el ledger.
- Ejemplo de permiso concedido (Grant) y actuación (Actuate) exitosa.
- Lista de eventos generados (ledger).

**3. Exportaciones de auditoría (página “Auditoría y Entrega”):**
- audit.json
- entries.csv
- events.csv
- checklist.txt

**4. (Opcional) Captura de la sección UART y MQTT mostrando funcionamiento del modo seguro/inseguro.**

##**Estructura esperada de entrega**

iot-secure-app/
├── audit.json
├── entries.csv
├── events.csv
├── checklist.txt
├── capturas/
│   ├── firmware_first_boot.png
│   ├── ota_verification.png
│   ├── blockchain_events.png
│   └── uart_mqtt_demo.png
└── notas.txt  # (explicación breve de contraseñas y mejoras)

##**Rúbrica de evaluación (10 pts)**
| Criterio                          | Descripción                                                                     | Puntos     |
| --------------------------------- | ------------------------------------------------------------------------------- | ---------- |
| **1. Ejecución y entorno**        | App funcional localmente, sin errores de importación o dependencias.            | 2 pts      |
| **2. UART y MQTT**                | Demostración de funcionamiento y explicación de amenazas simuladas.             | 1 pt       |
| **3. Firmware y contraseñas**     | Uso correcto de `first_boot`, detección de admin/admin y verificación de login. | 2 pts      |
| **4. OTA firmada**                | Generación y verificación de firmas RSA con actualización de versión OTA.       | 2 pts      |
| **5. Ledger y control de acceso** | Registro de lecturas, permisos y actuación auditables en el ledger.             | 2 pts      |
| **6. Auditoría final**            | Exportación completa (`audit.json`, CSVs, checklist.txt).                       | 1 pt       |
| **Total**                         |                                                                                 | **10 pts** |


