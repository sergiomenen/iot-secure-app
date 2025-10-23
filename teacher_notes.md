# 🧑‍🏫 Teacher Notes — IoT Secure App (Guía docente)

## ⏱️ Duración sugerida

**Opción A (3 sesiones × 90 min):**

1. **Sesión 1:** Introducción a amenazas IoT + práctica UART/MQTT (páginas 1–2).
2. **Sesión 2:** Seguridad de firmware y OTA firmada (página 2).
3. **Sesión 3:** Ledger / control de acceso / auditoría (páginas 3–4) + cierre.

**Opción B (2 sesiones + trabajo autónomo):**

* Dos sesiones de 2 h 30 min en laboratorio + 1 h de trabajo individual (capturas y entrega).

---

## 💬 Preguntas de discusión en clase

1. ¿Qué riesgos supone dejar interfaces UART accesibles en un producto IoT real?
2. ¿Por qué los “default credentials” siguen siendo un problema crítico en despliegues industriales?
3. ¿Qué ventajas y limitaciones tiene una bitácora encadenada (ledger) frente a una base de datos tradicional?
4. ¿Qué pasaría si la clave privada de firma OTA se filtrara? ¿Cómo mitigar ese escenario?
5. ¿Qué diferencias observas entre la seguridad “en tránsito” (MQTT/TLS) y “en reposo” (firmware cifrado o firmado)?

---

## ⚠️ Errores comunes en entregas

* **No ejecutar first_boot:** el alumno deja `admin/admin` y la evidencia no muestra el hash.
* **Firmas OTA sin verificación:** muestran “firmada” pero no demuestran la verificación correcta.
* **Ledger vacío:** no se registra ninguna lectura ni evento de actuador.
* **Export incompleto:** falta `audit.json` o los CSV.
* **Capturas genéricas:** no se ve claramente la funcionalidad o los mensajes de verificación (se recomienda incluir nombres de alumno y fecha en las capturas).

---

## 🧮 Evaluación recomendada

**Ponderación (10 pts, alineada con rúbrica del alumno):**

| Componente                 | Evidencia esperada                                                  | Puntos |
| -------------------------- | ------------------------------------------------------------------- | ------ |
| UART/MQTT                  | Captura mostrando DUMP SECRETS y manipulación/mitm local            | 1 pt   |
| Contraseñas / first_boot   | Captura con `attack_default_creds` y hash tras primer arranque      | 2 pts  |
| OTA firmada                | Captura o JSON de firma + verificación OK                           | 2 pts  |
| Ledger / Control de acceso | Captura con entradas, permisos y evento Actuated                    | 2 pts  |
| Export Auditoría           | Archivos `audit.json`, `entries.csv`, `events.csv`, `checklist.txt` | 2 pts  |
| Informe / Reflexión        | Nota breve sobre mitigaciones o mejora de seguridad                 | 1 pt   |

> Evaluar principalmente **por evidencia**:
>
> * Capturas visibles de la interfaz Streamlit.
