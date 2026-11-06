# 03. Seguridad Anti-SSRF y Aislamiento (`jg_plugin_conversational`)

[← 02. Herramientas](02_tools_specification.md) | [04. Testing y CI/CD →](04_testing_quality_cicd.md)

---

## 1. Módulo Autónomo Anti-SSRF (`ssrf_guard.py`)

Al consumir feeds RSS o APIs meteorológicas externas, el plugin implementa su propio guardián anti-SSRF sin acoplar el Core de `jg_agente`:
1. **Validación de Protocolo:** Rechazo estricto de esquemas no web (`file://`, `ftp://`).
2. **Filtrado de Rangos Privados e IPs de Metadatos Cloud:**
   - RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
   - Loopback (`127.0.0.0/8`, `::1`).
   - Metadatos AWS/GCP/Azure (`169.254.169.254`).
3. **DNS Pinning anti-TOCTOU:** Resolución previa y fijación de la dirección IP antes de emitir la llamada con `httpx.AsyncClient`.

---

## 2. Aislamiento de Red en Docker Compose

En `docker-compose.yml`, el servicio `jg_agente_conversacional`:
- No monta el socket de Docker (`/var/run/docker.sock`).
- Solo expone el puerto HTTP `8001` hacia la red interna `jg_network`.
- Tiene una base de datos PostgreSQL dedicada en `jg_agente_postgres` (5433), aislada de las bases de datos de DevOps y DatosGob.

