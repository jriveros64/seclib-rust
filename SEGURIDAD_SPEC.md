# SEGURIDAD_SPEC.md — Especificación técnica de la capa de seguridad transversal

> **Propósito:** especificación implementable para Claude Code. Define la capa de seguridad
> estándar reutilizable por cualquier proyecto (web, SaaS, servicios internos).
> No es un checklist de buenas intenciones: cada sección tiene decisiones tomadas, librerías,
> parámetros y criterios de aceptación verificables. Donde diga DEBE, es obligatorio;
> donde diga NUNCA, es bloqueante en revisión.

---

## 0. Alcance, supuestos y modelo de amenaza

**Supuestos de diseño (no negociables):**

1. El sistema se despliega en un **servidor externo (VPS/cloud) que se asume hostil o comprometible**: el proveedor puede fallar, otro tenant puede escapar de su aislamiento, un atacante puede obtener shell. Consecuencia: la seguridad NUNCA depende solo del perímetro del servidor. Datos sensibles cifrados a nivel de aplicación, secretos con alcance mínimo, logs replicados fuera del servidor, salida de red restringida.
2. **Todo input es hostil**: requests, archivos subidos, respuestas de APIs externas (incluido el banco), webhooks, variables de entorno inesperadas.
3. **Deny by default**: lo no explícitamente permitido está prohibido (endpoints, permisos, tipos de archivo, dominios de salida, puertos).
4. **Fail closed**: si un control de seguridad falla (no se puede validar el token, ClamAV caído, no responde el IdP), la operación se rechaza. NUNCA "si falla la validación, dejar pasar".
5. La capa es **transversal**: se implementa una vez como librería interna (`seclib`) + plantilla de infraestructura, y cada proyecto la consume por configuración. Los proyectos NUNCA copian/pegan código de seguridad ni lo reimplementan.

**Stack de referencia** (ajustable por proyecto vía config, no por reescritura):
Python 3.12+, FastAPI, Pydantic v2, PostgreSQL 15+, Docker Compose, reverse proxy Caddy (o Nginx), IdP Authentik o Keycloak autohospedado, Redis (rate limit / cola), worker Celery o RQ, ClamAV (clamd).

**Arquitectura de referencia:**

```
Internet
   │
[Caddy/Nginx: TLS, límites, rate-limit L7]        ← única pieza expuesta
   │
   ├── /auth/*  → [IdP: Authentik/Keycloak]        (contenedor propio)
   ├── /api/*   → [App FastAPI + seclib]           (contenedor propio, non-root)
   │                   │
   │                   ├── [PostgreSQL]            (red interna, sin puerto publicado)
   │                   ├── [Redis]                 (red interna)
   │                   └── cola → [Worker archivos] (contenedor aislado, sin salida a internet)
   │                                   └── [clamd]  (red interna)
   └── logs → syslog/Loki EXTERNO al servidor
```

**Componentes de la capa (módulos de `seclib`):**
`seclib.auth` (OIDC/JWT), `seclib.authz` (roles/permisos/tenancy), `seclib.secrets` (carga y cifrado), `seclib.http` (cliente saliente endurecido), `seclib.files` (pipeline de archivos), `seclib.crypto` (cifrado de campos), `seclib.logging` (log estructurado + auditoría), `seclib.middleware` (headers, request-id, límites), `seclib.testing` (fixtures y tests de seguridad reutilizables).

---

## 1. Autenticación (seclib.auth)

**Decisión:** NUNCA implementar autenticación propia. Delegación total en IdP autohospedado (Authentik o Keycloak) mediante OpenID Connect. `seclib.auth` solo implementa: cliente OIDC, validación de tokens, gestión de sesión.

### 1.1 Flujos permitidos

| Tipo de cliente | Flujo | Notas |
|---|---|---|
| Web app con backend | Authorization Code **+ PKCE** | PKCE siempre, aunque haya client_secret |
| SPA / frontend puro | Authorization Code + PKCE, cliente público | NUNCA implicit flow |
| Servicio máquina-a-máquina | Client Credentials | scopes mínimos por servicio |
| App escritorio/CLI | Authorization Code + PKCE con loopback redirect | NUNCA device-code si hay navegador |

NUNCA: Resource Owner Password Credentials (ROPC), implicit flow, tokens en query string.

### 1.2 Validación de tokens (cada request, en backend)

Librería: `PyJWT[crypto]` o `authlib.jose`. Implementar UNA función `verify_token()` en `seclib.auth` y prohibir cualquier otra validación en los proyectos.

Reglas exactas:

- Algoritmos aceptados: lista blanca `["RS256"]` (o `ES256`), pasada explícitamente a `jwt.decode(algorithms=[...])`. NUNCA aceptar el `alg` del header sin lista blanca. Rechazar `none` y `HS256` para tokens del IdP (previene confusión de clave pública usada como secreto HMAC).
- Claves: obtenidas del endpoint JWKS del IdP, seleccionadas por `kid`. Cache de JWKS con TTL 1 h y refetch automático ante `kid` desconocido (rotación de claves). Si el JWKS no responde y no hay cache válido → **fail closed** (503, no 200).
- Claims obligatorios validados: `iss` (igualdad exacta con el emisor configurado), `aud` (debe contener el client_id/audience del proyecto), `exp`, `iat`, `nbf` con leeway máximo 60 s.
- `sub` es el identificador estable del usuario. NUNCA usar `email` como clave primaria de identidad (los emails cambian y se reasignan).
- Reloj del servidor sincronizado con `chrony` (JWT depende del reloj; ver §8).

### 1.3 Tiempos de vida y revocación

- Access token: **15 minutos** (configurar en el IdP).
- Refresh token: **rotación obligatoria en cada uso** con detección de reuso: si se presenta un refresh token ya rotado → revocar la familia completa de tokens de esa sesión (Authentik/Keycloak lo soportan; activarlo).
- Sesión web absoluta: máximo 12 h; inactividad: 60 min (configurable por proyecto, nunca mayor).
- Logout: llamar al endpoint de revocación del IdP (`/revoke`) + `end_session_endpoint` + destruir sesión local. Borrar la cookie NO es logout.
- Revocación intra-vida del access token: no existe con JWT puro; se mitiga con vida de 15 min. Para acciones críticas (cambiar permisos, exportar datos financieros, eliminar), DEBE consultarse el estado del usuario en BD/IdP en el momento (no confiar solo en el token).

### 1.4 Manejo del token en el navegador

- Patrón obligatorio: **BFF (Backend For Frontend)**. Los tokens viven en el backend; el navegador solo recibe cookie de sesión opaca.
- Cookie: nombre con prefijo `__Host-` (fuerza Secure, sin Domain, Path=/), `HttpOnly`, `Secure`, `SameSite=Lax`. NUNCA tokens en `localStorage` ni `sessionStorage` (robables por cualquier XSS).
- Sesiones server-side en Redis con ID de 256 bits generado con `secrets.token_urlsafe(32)`.

### 1.5 MFA y políticas de cuenta (configurar en el IdP)

- TOTP obligatorio para: roles de administración y cualquier rol con lectura de datos financieros. Ofrecido (no obligatorio) al resto.
- Recuperación de contraseña: gestionada por el IdP. Tokens de un solo uso, expiración ≤ 30 min, invalidados al cambiar la contraseña.

### 1.6 Excepción: si un proyecto exige contraseñas locales

Solo con justificación escrita. Entonces:

- Hash: **Argon2id** (`argon2-cffi`) con `time_cost=3`, `memory_cost=65536` (64 MiB), `parallelism=4`. Alternativa aceptable: bcrypt cost ≥ 12. NUNCA: MD5, SHA-1, SHA-256 sin KDF, PBKDF2 con < 600k iteraciones.
- Política: longitud mínima 12, máxima ≥ 128, sin reglas de composición arbitrarias, sin expiración periódica forzada (alineado a NIST 800-63B). Verificar contra contraseñas filtradas vía API k-anonymity de HaveIBeenPwned (se envían solo 5 caracteres del hash SHA-1; nunca la contraseña).
- Comparaciones de secretos siempre con `secrets.compare_digest` / `hmac.compare_digest` (tiempo constante).

### 1.7 Anti fuerza bruta y anti enumeración

- Rate limit de login: 5 intentos / 15 min por cuenta **y** 20 / 15 min por IP (las dos dimensiones; solo IP se evade con botnets, solo cuenta permite bloquear a la víctima).
- Backoff progresivo, no bloqueo permanente automático (el bloqueo permanente permite DoS contra usuarios).
- Anti-enumeración: login, registro y recuperación devuelven exactamente el mismo mensaje y código HTTP exista o no la cuenta ("Si el correo existe, enviamos instrucciones"). Igualar tiempos de respuesta (ejecutar el hash aunque el usuario no exista, con un hash dummy).
- CAPTCHA/turnstile a partir del tercer intento fallido (configurable).

**Criterios de aceptación §1 (tests automáticos obligatorios):**

- Token con `alg: none` → 401. Token HS256 firmado con la clave pública → 401.
- Token expirado (exp − 2 min) → 401; con leeway 60 s: exp − 30 s → 200.
- `aud` de otro proyecto → 401. `iss` alterado → 401.
- Refresh token reutilizado → toda la sesión revocada (el access siguiente falla).
- Respuesta de login con usuario inexistente == respuesta con contraseña errónea (mismo cuerpo, mismo status, delta de tiempo < 100 ms en test).
- Cookie de sesión presenta `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`.
- Con IdP caído (mock 500 en JWKS y sin cache): endpoints protegidos → 503, nunca 200.

---

## 2. Autorización, perfiles y multi-tenancy (seclib.authz)

**Modelo:** RBAC (roles → permisos) + **scoping por recurso** (tenant/propietario). Los roles viajan en el token (claims); los permisos finos y la pertenencia de recursos se resuelven server-side contra BD.

### 2.1 Deny by default, verificable por máquina

- Toda ruta DEBE declarar su requisito: `@requires(Permission.X)` o `@public` explícito. Un endpoint sin declaración NO se registra: `seclib` recorre el router en el arranque y **aborta el boot** si encuentra rutas sin declaración. Además, test que enumera rutas y falla si alguna carece de política.
- La verificación ocurre en dependencia/middleware del backend. Ocultar botones en el frontend NO es control de acceso (el frontend es solo UX).

### 2.2 Definición central de permisos

```python
# seclib/authz/permissions.py — única fuente de verdad
class Permission(StrEnum):
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    FILES_UPLOAD = "files:upload"
    FINANCE_READ = "finance:read"
    FINANCE_EXPORT = "finance:export"
    ADMIN = "admin:*"

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "viewer":  frozenset({Permission.USERS_READ}),
    "analyst": frozenset({Permission.USERS_READ, Permission.FINANCE_READ, Permission.FILES_UPLOAD}),
    "admin":   frozenset(Permission),  # revisado, no implícito
}
```

- Mapa rol→permisos versionado en código o tabla, en UN solo lugar. PROHIBIDO `if user.role == "admin"` disperso por el código (regla de lint/grep en CI: cualquier comparación literal de rol fuera de `seclib.authz` es bloqueante).
- Mínimo privilegio: cada rol nuevo parte vacío y se le agregan permisos con justificación en el PR.

### 2.3 Autorización a nivel de objeto (anti-IDOR) — la falla nº 1 real

- Todo modelo de datos accesible por usuarios lleva `tenant_id` (u `owner_id`) **NOT NULL**.
- Patrón repositorio obligatorio: las funciones de acceso a datos reciben `tenant_id` como **parámetro posicional no opcional**; no existe función "get by id" sin tenant. Grep de CI: llamadas a `.get(` sobre modelos sensibles fuera del repositorio son bloqueantes.
- Segunda capa (defensa en profundidad): **PostgreSQL Row Level Security** activado en tablas multi-tenant; la app fija `SET LOCAL app.tenant_id = $1` por transacción y la policy `USING (tenant_id = current_setting('app.tenant_id')::uuid)` filtra aunque el código tenga un bug.
- IDs expuestos al cliente: **UUIDv4** (o ULID). NUNCA autoincrementales en URLs/JSON (facilitan enumeración y filtran volumen de negocio).
- Respuesta ante recurso ajeno: **404**, no 403 (403 confirma que el recurso existe).

### 2.4 Acciones sensibles

- Cambios de rol/permiso, exportaciones masivas, borrados: requieren (a) permiso específico, (b) re-verificación de estado en BD (no solo token), (c) registro de auditoría (§9), y para admin (d) re-autenticación reciente (`auth_time` < 10 min o step-up MFA del IdP).
- Un usuario NUNCA puede modificar su propio rol ni aprobar sus propias solicitudes (regla explícita en la policy, con test).

**Criterios de aceptación §2:**

- Test de matriz completa: por cada endpoint × cada rol, status esperado (200/403/404) declarado en tabla; el test falla si la tabla no cubre todos los endpoints.
- Test IDOR: usuario A (tenant 1) solicita recurso de B (tenant 2) por ID directo → 404. Repetir en listados (el recurso ajeno no aparece).
- Test de boot: agregar ruta sin `@requires` → la app no arranca.
- Con RLS activo: query manual sin `app.tenant_id` seteado → 0 filas.

---

## 3. Secretos y material criptográfico (seclib.secrets, seclib.crypto)

### 3.1 Reglas de existencia

- NUNCA un secreto en: código fuente, historial git, imágenes Docker (ni en layers intermedios), logs, mensajes de error, variables de frontend, tickets/chat.
- Desarrollo: `.env` local (en `.gitignore`) con valores dummy o de sandbox. Producción: secretos inyectados por `docker secrets` / systemd `LoadCredential` / variables definidas en el host — o repositorio de infraestructura con **sops + age** (secretos cifrados en git, clave age solo en el servidor y en respaldo offline).
- Carga en la app: `pydantic-settings` con esquema tipado; la app **aborta el arranque** si falta un secreto requerido (fail closed; nada de defaults silenciosos como `SECRET_KEY = "changeme"` — grep de CI bloqueante para defaults de secretos).

### 3.2 Higiene de repositorio

- Pre-commit hook: `gitleaks protect --staged` en todos los repos (instalación documentada en el README de la plantilla).
- CI en cada push: `gitleaks detect` sobre el rango + job semanal `trufflehog git file://. --only-verified` sobre **historial completo**.
- Si un secreto tocó el repo alguna vez: se considera comprometido → rotar de inmediato. Reescribir historial es opcional; la rotación es obligatoria.

### 3.3 Cifrado de datos sensibles a nivel de aplicación

(Consecuencia directa del supuesto "servidor comprometible": el cifrado de disco del proveedor NO protege contra un atacante con shell o contra un dump de BD.)

- Campos a cifrar en BD: tokens/credenciales de terceros (banco, ERP), números de cuenta, y todo dato que un dump de la tabla no deba revelar.
- Primitiva: **AES-256-GCM** vía `cryptography` (o Fernet si no se necesita AAD). Nonce de 96 bits aleatorio por operación, NUNCA reutilizado con la misma clave. Guardar `key_version || nonce || ciphertext || tag`.
- AAD: incluir `tenant_id` + nombre de campo como associated data formateado bajo la convención `{len(tenant)}:{tenant}:{field}` (length-prefixed por caracteres, ej. `8:tenant_a:api_key`). Esto garantiza que un ciphertext copiado a otra fila/tenant no descifra y previene ataques de extensión por colisiones de concatenación.
- Jerarquía de claves: clave maestra (KEK) fuera de la BD (secreto de entorno / age); claves de datos (DEK) por tabla o por tenant, cifradas con la KEK, almacenadas con versión. Rotación: nueva versión de DEK, re-cifrado perezoso o batch; la KEK rota ≤ 12 meses o ante sospecha.
- PROHIBIDO diseñar criptografía propia (modos, paddings, "ofuscaciones"). Solo primitivas de `cryptography` en los modos indicados.

### 3.4 Rotación y alcance

- Credenciales de API bancaria/ERP: rotación ≤ 90 días y ante cualquier sospecha; scopes mínimos (si solo se lee cartola, NUNCA pedir permiso de pago).
- Un secreto = un uso = un alcance. NUNCA la misma credencial para dev y prod, ni compartida entre proyectos.
- Inventario de secretos (archivo `SECRETS_INVENTORY.md` por proyecto): nombre, dónde vive, quién lo puede rotar, procedimiento de rotación, fecha de última rotación. Sin valores, solo metadatos.

**Criterios de aceptación §3:**

- CI con gitleaks/trufflehog en verde; test que planta un secreto dummy y verifica que el hook lo bloquea.
- Arranque sin `DATABASE_URL` (u otro requerido) → exit code ≠ 0 con mensaje claro, no arranque degradado.
- Test de cifrado: ciphertext de campo movido a otro tenant → falla de descifrado (AAD). Nonce distinto en dos cifrados del mismo plaintext.
- `docker history` de la imagen final no revela secretos en ningún layer.

---

## 4. Integraciones externas: APIs bancarias, ERP, webhooks (seclib.http)

**Principio:** el sistema externo es no confiable aunque sea un banco. Su respuesta puede venir malformada, manipulada (si su lado fue comprometido) o simplemente cambiar sin aviso.

### 4.1 Cliente saliente único y endurecido

Todo tráfico saliente pasa por `seclib.http.SecureClient` (wrapper de `httpx`). PROHIBIDO usar `requests`/`httpx` directo en los proyectos (regla de import-lint en CI).

Configuración fija del cliente:

- TLS ≥ 1.2, verificación de certificado SIEMPRE (`verify=True` con CAs del sistema). `verify=False` es bloqueante en revisión de código sin excepciones (`bandit B501` como gate de CI). Para el banco: opcionalmente pinning del certificado o de la CA emisora, con procedimiento de actualización documentado (el pinning mal gestionado causa caídas).
- Timeouts explícitos SIEMPRE: `connect=5s, read=30s, write=10s, pool=5s`. NUNCA requests sin timeout (cuelgan workers y son un DoS autoinfligido).
- Reintentos: máximo 3, backoff exponencial con jitter (1 s, 2 s, 4 s ± aleatorio), **solo** para métodos idempotentes (GET, PUT con idempotency key) y errores de red/5xx. NUNCA reintentar un POST de operación financiera sin idempotency key.
- Circuit breaker por servicio externo (p. ej. `purgatory` o implementación simple en Redis): tras N fallos consecutivos, abrir circuito X segundos y responder degradado. Evita cascadas y martilleo al proveedor.
- Rate limit propio hacia cada proveedor según su contrato (token bucket en Redis).

### 4.2 Validación de respuestas externas

- Todo response body se parsea contra un esquema **Pydantic estricto**: `model_config = ConfigDict(extra="forbid", strict=True)`. Campos numéricos financieros: `Decimal`, NUNCA `float` (errores de redondeo en dinero son un bug de integridad).
- Rango y coherencia: montos dentro de límites plausibles configurables, fechas no futuras donde aplique, monedas en lista blanca. Respuesta que no valida → se rechaza y se registra; NUNCA "guardar lo que llegó y ver después".
- Los datos externos son entrada de usuario a efectos de XSS/SQLi: se insertan con queries parametrizadas y se escapan al renderizar, igual que cualquier input.

### 4.3 Webhooks entrantes

- Verificación de firma HMAC (según proveedor) con `hmac.compare_digest`, calculada sobre el **cuerpo crudo** (bytes) antes de parsear JSON.
- Ventana de timestamp: rechazar eventos con `|now − timestamp| > 5 min` (anti-replay) y deduplicar por `event_id` (tabla/Redis con TTL 24 h → idempotencia).
- Endpoint de webhook: sin sesión, solo firma; responder 200 rápido y procesar en worker (no dar al proveedor visibilidad del tiempo de procesamiento interno).
- Si el proveedor publica IPs de origen: allowlist adicional en el proxy. La firma sigue siendo el control principal (las IPs cambian).

### 4.4 SSRF y egress

- Si alguna función descarga URLs provistas por usuarios: resolver DNS primero y **bloquear destinos privados**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16 (metadata cloud), ::1, fd00::/8. Re-validar tras redirects (máx. 3). Solo esquemas http/https.
- Egress allowlist a nivel de firewall del servidor (§8): el servidor solo alcanza los dominios/IPs declarados (IdP externo si aplica, API banco, ERP, repos de paquetes, syslog remoto). Un atacante con shell no puede exfiltrar a un destino arbitrario ni descargar herramientas. Esta es una de las mitigaciones más rentables del supuesto "servidor comprometido".

### 4.5 Registro de llamadas financieras

- Por cada llamada al banco/ERP: timestamp, endpoint, método, status, duración, request_id de correlación, hash del payload (no el payload). NUNCA registrar tokens, credenciales ni números de cuenta completos (últimos 4 dígitos como máximo).

**Criterios de aceptación §4:**

- Test: respuesta del "banco" (mock) con campo extra → rechazo con error controlado, nada persistido.
- Test: monto como float con 0.1+0.2 → el esquema lo fuerza a Decimal o rechaza.
- Test webhook: firma inválida → 401; timestamp de hace 10 min → 400; mismo event_id dos veces → segunda es no-op.
- Test SSRF: URL de usuario apuntando a 169.254.169.254 y a un hostname que resuelve a 127.0.0.1 → bloqueadas.
- Grep CI: cero `verify=False`, cero `requests.` fuera de seclib, cero llamadas sin timeout.

---

## 5. Carga y procesamiento de archivos (seclib.files) — CSV, XLSX, PDF

**Principio:** todo archivo es hostil. El objetivo no es solo "detectar virus": es que un archivo malicioso **no pueda ejecutar nada, agotar recursos, ni inyectar datos**, y que si el parser es explotado, el daño quede confinado a un proceso desechable.

### 5.1 Pipeline obligatorio (en orden, fail closed en cada paso)

```
recepción → límites → validación de identidad de archivo → almacenamiento en cuarentena
→ escaneo AV → parsing EN WORKER AISLADO → validación de esquema/contenido
→ carga transaccional a BD → archivo a almacenamiento definitivo cifrado o borrado
```

Ningún paso es opcional. Si clamd no responde → el archivo queda en cuarentena y el usuario recibe "en procesamiento", NUNCA se salta el escaneo.

### 5.2 Recepción y límites

- Límite de tamaño en DOS capas: reverse proxy (`client_max_body_size` / equivalente Caddy) y aplicación. Valores por defecto: CSV 20 MB, XLSX 20 MB, PDF 50 MB (config por proyecto).
- Streaming a disco de cuarentena con nombre `uuid4()`; NUNCA cargar el archivo entero a memoria ni usar el filename original en rutas (path traversal: `../../app/main.py`). El nombre original se guarda solo como metadato en BD, saneado (`unicodedata.normalize` + allowlist de caracteres) y escapado al mostrarse.
- Directorio de cuarentena y de almacenamiento: fuera del webroot y del árbol de la app, montado `noexec,nosuid,nodev`, permisos 0640, owner el usuario del worker.
- Rate limit de subida por usuario (p. ej. 20 archivos/hora) y cuota de almacenamiento por tenant.

### 5.3 Identidad del archivo (antes de tocar su contenido)

- Extensión en allowlist exacta por endpoint: `{".csv", ".xlsx", ".pdf"}`. Rechazar dobles extensiones (`informe.pdf.exe`) evaluando **solo el último sufijo** y rechazando si hay sufijos ejecutables en cualquier posición.
- Tipo real por magic bytes con `python-magic`: `text/csv|text/plain` para CSV, `application/zip` + estructura OOXML válida para XLSX, `%PDF-` para PDF. El `Content-Type` del navegador se IGNORA como control (es declarativo).
- Coherencia extensión ↔ tipo real obligatoria. XLSX es un ZIP: verificar que contiene `[Content_Types].xml` y `xl/workbook.xml` antes de aceptarlo como XLSX.
- **Anti zip-bomb (XLSX):** antes de parsear, inspeccionar el ZIP con `zipfile`: rechazar si tamaño descomprimido total > 200 MB, ratio de compresión > 100:1, > 1 000 entradas, o cualquier entrada con path traversal (`..` o ruta absoluta) — verificación manual de nombres, no `extractall` directo.

### 5.4 Escaneo antivirus

- ClamAV como daemon (`clamd`) en contenedor propio, red interna; la app envía por socket (`INSTREAM`). Firmas actualizadas por `freshclam` (el contenedor de clamd es de los pocos con salida a internet, solo a mirrors de firmas).
- Positivo → archivo movido a `quarantine/`, evento de auditoría severidad alta, alerta (§9). NUNCA borrar silenciosamente (se pierde evidencia).
- El AV es UNA capa, no LA defensa: detecta malware conocido; no detecta un exploit nuevo contra tu parser. Por eso existe §5.5.

### 5.5 Parsing en worker aislado — el control central de esta sección

El parsing NUNCA ocurre en el proceso web. Contenedor worker con:

- Usuario non-root, `read_only: true` (solo `/tmp` escribible con `tmpfs`), `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`.
- **Sin salida a internet**: solo alcanza BD/Redis en la red interna. Un exploit del parser no puede descargar payload ni exfiltrar.
- Límites duros: memoria (p. ej. `mem_limit: 1g`), CPU, y timeout por archivo (p. ej. 120 s) con kill del proceso hijo. Un archivo diseñado para colgar el parser mata SU proceso, no el sistema.
- Cada archivo se procesa en proceso hijo desechable; crash del parser = archivo marcado "corrupto/rechazado", el worker sigue.

### 5.6 Reglas por formato

**XLSX** (`openpyxl`):

- Abrir con `load_workbook(path, read_only=True, data_only=True)`. openpyxl no ejecuta macros, pero por política: **rechazar `.xlsm`, `.xlsb`, `.xls`** salvo requerimiento explícito del proyecto (y jamás abrirlos con Excel real/COM automation en servidor).
- XXE: openpyxl usa `et_xmlfile`/lxml sin resolución de entidades externas por defecto; NUNCA re-parsear los XML internos con `xml.etree` directo; si se necesita, `defusedxml`.
- Límites de contenido: máx. filas/columnas configurables (default 500 000 celdas); cortar y rechazar por encima.
- Ignorar (no evaluar jamás) fórmulas: se lee `data_only=True`; si la celda no tiene valor cacheado, se trata como vacía o se rechaza según config. NUNCA implementar evaluación de fórmulas.

**CSV:**

- Encoding: intentar UTF-8 estricto; fallback única a Latin-1 solo si el proyecto lo declara. Delimitador declarado por config o sniffing sobre las primeras 4 KB solamente.
- Validación fila a fila contra esquema (`pandera` o Pydantic por fila): columnas exactas esperadas (`extra=forbid` conceptual), tipos, rangos, montos como `Decimal`. Política de errores: rechazar archivo completo si > N filas inválidas (default N=0 para datos financieros: todo o nada, transaccional).
- **CSV/Formula injection:** cualquier celda que comience con `=`, `+`, `-`, `@`, TAB o CR se sanea (prefijo `'`) **en toda exportación** que el sistema genere, y se marca/rechaza en importación según config. El riesgo: un CSV re-abierto en Excel por un humano ejecuta la fórmula (`=HYPERLINK(...)`, DDE) en SU máquina.
- Carga a BD: SIEMPRE parametrizada (el contenido del archivo es input de usuario → vector de SQLi). `COPY` de PostgreSQL solo desde archivo ya validado y generado por el sistema, nunca el original.

**PDF:**

- Solo parsing estructural/extracción de texto: `pikepdf` (validación/reparación, detección de cifrado y JavaScript embebido) + `pdfminer.six` para texto. NUNCA renderizar PDFs de usuarios con stacks basados en visores completos en el proceso principal; si el proyecto exige render (thumbnails), hacerlo únicamente dentro del worker aislado de §5.5 y tratarlo como el paso de mayor riesgo del sistema.
- Política por defecto: rechazar PDFs con JavaScript embebido, acciones `/Launch`, `/OpenAction` hacia ejecución, o archivos incrustados (pikepdf permite inspeccionarlo). Rechazar PDFs cifrados (no se pueden escanear con garantías).
- Límites: máx. páginas (default 500), máx. objetos, timeout §5.5.

### 5.7 Entrega de archivos a usuarios

- SOLO vía endpoint autenticado con verificación de permiso sobre ESE archivo (anti-IDOR §2.3). NUNCA servir el directorio de archivos por el proxy.
- Headers de descarga: `Content-Disposition: attachment; filename="saneado.ext"`, `X-Content-Type-Options: nosniff`, `Content-Type` real almacenado (no adivinado). Nunca `inline` para contenido subido por usuarios (un HTML/SVG servido inline ejecuta scripts en tu origen → XSS almacenado).
- Almacenamiento definitivo cifrado (§3.3) si el archivo contiene datos financieros; retención y borrado según política del proyecto.

**Criterios de aceptación §5 (suite de archivos maliciosos de prueba, incluida en seclib.testing):**

- EICAR → detectado, en cuarentena, alerta emitida.
- `factura.pdf.exe`, PDF renombrado a .csv, XLSX sin `[Content_Types].xml` → rechazados en §5.3.
- Zip-bomb sintética (10 KB → 1 GB) → rechazada por ratio antes de parsear.
- CSV con celda `=HYPERLINK("http://evil")` → importación según política + toda exportación la re-escribe con `'=`.
- XLSX de 10^6 filas → rechazo por límite, worker vivo, memoria bajo el límite.
- PDF con JavaScript embebido y PDF cifrado → rechazados con motivo específico.
- Filename `../../etc/cron.d/x` → almacenado como UUID, metadato saneado, sin archivo fuera de cuarentena.
- Matar clamd → subida queda "en procesamiento", cero archivos parseados (fail closed).

---

## 6. Base de datos (PostgreSQL)

### 6.1 Acceso y privilegios

- Tres roles separados: `app_user` (DML sobre su esquema: SELECT/INSERT/UPDATE/DELETE; **sin** CREATE/DROP/ALTER, sin SUPERUSER, sin acceso a otros esquemas), `migrator` (DDL, usado solo por el pipeline de migraciones), `readonly` (reportes/backups lógicos). La app corre SIEMPRE con `app_user`.
- Autenticación `scram-sha-256` (no md5, no trust). TLS entre app y BD incluso en red interna (`sslmode=verify-full` si hay certificados propios; mínimo `require`).
- PostgreSQL SIN puerto publicado al host ni a internet: solo red interna de Docker. `listen_addresses` restringido. NUNCA `0.0.0.0:5432` expuesto.

### 6.2 Queries

- 100 % parametrizado vía ORM (SQLAlchemy 2.x) o driver con placeholders. PROHIBIDO construir SQL con f-strings/`%`/`+` (gates de CI: `bandit B608`, `ruff S608`, y grep de `text(f"` ). Si se necesita SQL dinámico (columnas de orden), allowlist de identificadores en código, nunca interpolación del input.
- `statement_timeout` (p. ej. 30 s) y `idle_in_transaction_session_timeout` para `app_user`: una query hostil o con bug no bloquea la BD.

### 6.3 Cifrado y datos

- En tránsito: TLS (arriba). En reposo: cifrado de disco/volumen del proveedor **más** cifrado a nivel de aplicación (§3.3) para campos sensibles — el cifrado del proveedor no protege contra dump con credenciales robadas.
- Minimización: no guardar datos que no se usan. Números de tarjeta: NUNCA almacenar PAN completo (si un proyecto lo pidiera, la respuesta es tokenización con el proveedor de pago, no almacenamiento propio).
- RLS multi-tenant como segunda capa (§2.3).

### 6.4 Backups — con prueba de restauración

- `pgBackRest` o `WAL-G`: base full diaria + WAL continuo (RPO minutos). Destino EXTERNO al servidor (object storage de otro proveedor idealmente), cifrado con age/GPG cuya clave NO vive en el servidor de origen (si el atacante del servidor puede leer/borrar/descifrar los backups, no hay backups).
- Retención: 30 días diarios + 12 mensuales (ajustable). Backups inmutables o con bucket versioning + object lock si el storage lo permite (anti-ransomware).
- **Restore test mensual automatizado**: job que restaura el último backup en un contenedor limpio, corre migraciones/health checks y reporta. Backup no probado = backup inexistente. El resultado del job es visible (alerta si falla).

**Criterios de aceptación §6:**

- `app_user` ejecutando `DROP TABLE` / `CREATE TABLE` → error de permisos (test de integración).
- Conexión sin TLS → rechazada por `pg_hba.conf`.
- Test de inyección: input `' OR 1=1--` y `"; DROP TABLE...` en cada endpoint de búsqueda → tratados como literal (0 resultados), nunca error de sintaxis SQL (el error de sintaxis delata concatenación).
- Evidencia del último restore test (timestamp) con antigüedad < 35 días como check de CI/cron.

---

## 7. Capa web: salida, headers, CSRF, CORS, validación de entrada (seclib.middleware)

### 7.1 Validación de entrada (todos los endpoints)

- Modelos Pydantic con `extra="forbid"` en TODO body/query/path (mass assignment: un campo extra `{"role": "admin"}` en un update de perfil NUNCA debe llegar al modelo).
- Longitud máxima en todo string (default 1 000, explícito donde difiera), rangos en números, enums para valores cerrados. `Decimal` para dinero.
- Límite global de tamaño de request JSON (p. ej. 1 MB) y de profundidad de anidamiento; el proxy corta antes (§8).

### 7.2 Salida y XSS

- Templates Jinja2 con autoescape ON (default de FastAPI/Starlette templates). Uso de `| safe` / `Markup`: requiere comentario `# safe-reviewed:` con justificación; grep de CI lista todas las ocurrencias y el PR debe justificarlas.
- Datos de usuario en HTML: siempre escapados; en atributos: entre comillas; en JS embebido: NUNCA interpolar directamente (pasar por `json.dumps` + `<script type="application/json">` y leer del DOM).
- Si hay frontend SPA: mismo principio, prohibido `dangerouslySetInnerHTML`/`v-html` con datos de usuario sin sanitización (`DOMPurify` si es inevitable).

### 7.3 Headers de seguridad (middleware global, valores exactos)

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{aleatorio_por_request}';
  style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none';
  frame-ancestors 'none'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cache-Control: no-store            ← en respuestas con datos sensibles/autenticadas
```

- CSP sin `unsafe-inline` ni `unsafe-eval`: scripts inline solo con nonce por request. Si una librería de frontend lo exige, se documenta la excepción por proyecto con su riesgo.
- `X-Frame-Options: DENY` redundante con frame-ancestors, se incluye por compatibilidad.

### 7.4 CSRF

- Necesario porque la sesión es cookie (§1.4). `SameSite=Lax` mitiga pero NO basta (no cubre todos los vectores ni navegadores antiguos).
- Patrón: synchronizer token (token por sesión en Redis, embebido en forms/headers) o double-submit firmado. Obligatorio en todo POST/PUT/PATCH/DELETE con sesión de cookie. Los endpoints puramente Bearer-token (API M2M) están exentos (no hay cookie que forjar).
- Verificar además `Origin`/`Referer` contra allowlist en mutaciones (defensa adicional barata).

### 7.5 CORS

- Allowlist EXPLÍCITA de orígenes por proyecto (esquema+host+puerto exactos). NUNCA `*` con `allow_credentials=True` (el navegador lo rechaza, y los "workarounds" de reflejar el Origin recrean el problema: reflejar Origin arbitrario == `*`).
- Métodos y headers permitidos: solo los usados. `max_age` razonable (600 s).

### 7.6 Errores y rate limiting

- Handler global de excepciones: al cliente `{"error": "internal_error", "error_id": "<uuid>"}`; el detalle completo (stack, contexto) solo al log con ese `error_id` (correlación soporte↔log sin filtrar internals). `DEBUG=False` en prod verificado en arranque (si `DEBUG=True` y `ENV=prod` → abort).
- 404 genérico también para rutas de infraestructura (`/.env`, `/wp-admin`, `/.git`): mismo 404 que cualquier ruta (no confirmar stack por diferencias).
- Rate limiting L7 (`slowapi`/Redis): global por IP (p. ej. 100 req/min), estricto en login (§1.7), upload (§5.2), exportaciones y endpoints costosos. Respuesta 429 con `Retry-After`.

**Criterios de aceptación §7:**

- Test mass-assignment: PATCH de perfil con `{"role": "admin"}` → 422, rol intacto.
- Escáner de headers (test que hace GET y verifica cada header exacto de la tabla).
- Test CSRF: POST con cookie válida sin token → 403.
- Test CORS: preflight desde origen no listado → sin `Access-Control-Allow-Origin`.
- Test de error: endpoint que lanza excepción → cliente recibe error_id, el stack NO aparece en el body; el log contiene el error_id.
- ZAP baseline scan contra staging en CI: cero alertas High; Medium justificadas por escrito.

---

## 8. Servidor y despliegue: el servidor también es un objetivo

**Recordatorio del supuesto §0:** este servidor externo puede tener sus propias vulnerabilidades y ser comprometido. Las medidas §3.3 (cifrado app-level), §4.4 (egress restringido), §6.4 (backups externos con clave fuera del servidor) y §9.2 (logs replicados fuera) existen para que un compromiso del servidor NO sea un compromiso total. Esta sección reduce además la probabilidad del compromiso.

### 8.1 Sistema operativo (Ubuntu LTS / Debian)

- Acceso: SSH solo con llave (ed25519), `PasswordAuthentication no`, `PermitRootLogin no`, usuario administrativo con sudo, `fail2ban` (o equivalente nftables) sobre sshd. Cambiar el puerto SSH es opcional/cosmético; la llave es el control.
- Parches: `unattended-upgrades` activo para actualizaciones de seguridad; reinicios programados cuando el kernel lo exige (o `livepatch`). Un servidor sin parchear 6 meses invalida el resto del documento.
- Firewall `ufw`/nftables: **entrada** deny-by-default, abierto solo 80/443 (proxy) y SSH (idealmente restringido a IP fija o vía WireGuard); **salida** deny-by-default con allowlist (§4.4): DNS, NTP, repos del SO, mirrors ClamAV, APIs declaradas, destino de logs y backups. La salida restringida es inusual y valiosa: corta exfiltración y descarga de herramientas post-compromiso.
- `chrony` para NTP (JWT/TOTP dependen del reloj). `auditd` con reglas básicas (exec de binarios nuevos, cambios en /etc, uso de sudo).
- Nada más instalado en el host que Docker + agentes mínimos. El host no corre la app directamente.

### 8.2 Contenedores (Docker Compose de la plantilla)

Por servicio, en el compose de referencia:

```yaml
user: "10001:10001"            # non-root SIEMPRE
read_only: true                 # FS inmutable; tmpfs para /tmp
cap_drop: [ALL]                 # sin capabilities
security_opt: ["no-new-privileges:true"]
mem_limit / cpus                # límites de recursos por servicio
restart: unless-stopped
networks: [red interna específica]   # segmentación: web↔app, app↔db, app↔redis;
                                     # la BD NO comparte red con el proxy
```

- Imágenes: base `-slim` o distroless, versión fijada por digest (`python:3.12-slim@sha256:...`), reconstruidas al menos mensualmente (una imagen vieja congela vulnerabilidades). Escaneo `trivy image` en CI: bloqueo por CRITICAL/HIGH con fix disponible.
- NUNCA montar `/var/run/docker.sock` en un contenedor (equivale a root del host). NUNCA `privileged: true`. Puertos publicados: SOLO el proxy (80/443); todo lo demás sin `ports:`.
- Secretos a contenedores vía `docker secrets`/archivos con permisos, no `environment:` en el compose commiteado.
- Healthchecks en todos los servicios; el proxy solo enruta a upstreams sanos.

### 8.3 Reverse proxy (Caddy de referencia; Nginx equivalente documentado)

- TLS automático (Let's Encrypt), redirección 80→443, HTTP/2. TLS mínimo 1.2, suites modernas (defaults de Caddy son correctos; en Nginx, config de Mozilla "intermediate").
- Límites: tamaño de body por ruta (coherente con §5.2), timeouts de lectura/escritura, límite de conexiones por IP. Rate limit L7 básico además del de la app.
- Oculta versión/banner del servidor. No sirve directorios estáticos de datos, solo assets públicos del frontend.

### 8.4 Pipeline de despliegue

- Deploy SOLO desde CI, desde rama protegida (main) con tag; nunca `git pull` + edición manual en el servidor (deriva de configuración = agujeros invisibles). Infra como código: el servidor se puede reconstruir desde el repo de infraestructura + secretos age — esto es también el plan de recuperación §12.
- CI con permisos mínimos: la llave de deploy solo puede desplegar, no leer secretos de otros proyectos. Ramas protegidas, revisión obligatoria de PR (aunque el revisor sea Code + tú: el gate existe), gates de CI (§10-§11) bloqueantes.

**Criterios de aceptación §8:**

- `nmap` externo al servidor → solo 22 (o nada, si SSH via VPN), 80, 443.
- Desde un shell dentro del contenedor app: `curl https://dominio-no-listado` → bloqueado; `psql` a la BD → funciona (egress allowlist correcta y segmentación viva).
- `docker inspect` de cada servicio: User ≠ root, ReadonlyRootfs=true, CapDrop=ALL, sin docker.sock.
- `id` dentro del contenedor ≠ uid 0; `touch /x` → read-only file system.
- Reconstrucción completa del stack en servidor limpio desde el repo de infra: documentada y ejecutada al menos una vez (drill).

---

## 9. Logging, auditoría y detección (seclib.logging)

**Principio:** prevenir sin detectar es apostar a la perfección. Diseñar para responder a "¿alguien accedió indebidamente y hace cuánto?".

### 9.1 Log estructurado

- `structlog` con salida JSON: `timestamp` (UTC ISO8601), `level`, `event`, `request_id` (UUID por request, propagado a workers y llamadas salientes como header), `user_id`/`sub`, `tenant_id`, `ip`, `outcome`.
- `request_id` devuelto al cliente en header `X-Request-Id` (correlaciona reportes de usuarios con logs).

### 9.2 Los logs salen del servidor

- Envío near-real-time a destino EXTERNO (Loki/CloudWatch/syslog remoto/servicio de logs). Motivo directo del supuesto §0: un atacante con shell borra los logs locales; los remotos append-only son la evidencia. Retención: 90 días operativos, 12 meses para auditoría de accesos a datos financieros.

### 9.3 Eventos de auditoría obligatorios (canal `audit`, además del log técnico)

login éxito/fallo (con motivo), logout, refresh, cambio de rol/permiso (quién, a quién, antes/después), creación/desactivación de usuarios, acceso y **exportación** de datos financieros (quién, qué recurso, cuántos registros), subida de archivo (hash SHA-256, resultado del pipeline §5), positivo de AV, llamadas a API bancaria (§4.5), cambios de configuración, restauraciones de backup, accesos administrativos.

### 9.4 Qué NUNCA se registra

Contraseñas (ni fallidas: los "typos" de password son casi-passwords), tokens/cookies/API keys, contenido de archivos, PAN/número de cuenta completo (últimos 4 como máximo), datos personales innecesarios. Filtro de redacción central en `seclib.logging` (lista de nombres de campos: `password`, `token`, `secret`, `authorization`, `cookie`, `account_number` → `***`), aplicado antes de emitir, con test.

### 9.5 Alertas mínimas (config de referencia incluida)

- ≥ 10 logins fallidos / 5 min sobre una cuenta o desde una IP → alerta.
- Login exitoso de rol admin desde IP/país nunca visto → alerta inmediata.
- Exportación > N registros o fuera de horario hábil → alerta.
- Positivo ClamAV, spike de 5xx, spike de 403/404 (scraping/enumeración), circuit breaker abierto hacia el banco, gitleaks positivo en CI, restore test fallido → alerta.
- Canal: correo + mensajería (webhook), con runbook §12 enlazado en cada alerta.

**Criterios de aceptación §9:**

- Test de redacción: log de un request con `{"password": "x", "authorization": "Bearer y"}` → el sink recibe `***` en ambos.
- Cada evento de §9.3 tiene test que lo dispara y verifica su emisión en canal `audit` con los campos completos.
- Simulacro: 15 logins fallidos → alerta recibida end-to-end en < 5 min.
- Verificación de que los logs llegan al destino externo (health check del shipper alertado si cae).

---

## 10. Dependencias y cadena de suministro

- Lockfile con **hashes**: `uv` (o `pip-compile --generate-hashes`) e instalación con `--require-hashes` / verificación de uv. Sin hash, un mirror comprometido o un re-upload malicioso pasa inadvertido. En frontend: `package-lock.json` + `npm ci` (nunca `npm install` en CI).
- Auditoría en CI en cada PR: `pip-audit` + `trivy fs .` (Python) y `npm audit --omit=dev` (frontend). Gate: bloqueo por CRITICAL/HIGH con fix disponible; excepciones con vencimiento escrito (máx. 30 días), no permanentes.
- **Política de paquete nuevo** (checklist en el PR que lo introduce): nombre verificado carácter a carácter contra typosquatting (`reqeusts`, `python-dateutils`); > 6 meses de existencia y mantenimiento activo o justificación; sin instalación de scripts post-install sospechosos; alternativa de stdlib considerada. Los ataques por paquete malicioso en PyPI/npm son rutina, no teoría.
- Actualizaciones: Renovate/Dependabot con PRs automáticos; parches de seguridad se priorizan; majors se revisan con changelog. NUNCA automerge de majors.
- Fijar también las GitHub Actions por SHA (`uses: actions/checkout@<sha>`), no por tag mutable.
- Modelos/paquetes de IA o binarios descargados en runtime: PROHIBIDO descargar en producción desde internet en caliente; todo entra por la imagen construida en CI (coherente con egress §4.4).

**Criterios de aceptación §10:** build de CI falla si el lockfile no tiene hashes; falla con una CVE HIGH inyectada de prueba; `npm ci`/`--require-hashes` verificado en los scripts de build.

---

## 11. Pruebas de seguridad: Definition of Done

Ningún proyecto se considera terminado ni desplegable si esta batería no está en verde. `seclib.testing` provee fixtures y suites parametrizables para no reescribirlas por proyecto.

### 11.1 Estático (cada PR, bloqueante)

| Herramienta | Cobertura | Gate |
|---|---|---|
| `ruff` (reglas `S`, flake8-bandit) | patrones inseguros en Python | error = bloqueo |
| `bandit -ll` | SQLi (B608), verify=False (B501), subprocess, yaml.load, pickle | HIGH = bloqueo |
| `gitleaks` | secretos en el diff | hallazgo = bloqueo |
| `pip-audit` / `trivy` | CVEs en dependencias e imagen | CRIT/HIGH con fix = bloqueo |
| `mypy --strict` en seclib | errores de tipo que esconden bypasses | error = bloqueo |
| Greps de política | `requests.` fuera de seclib, `verify=False`, `text(f"`, comparación literal de roles, `\| safe` sin `# safe-reviewed` | hallazgo = bloqueo |

### 11.2 Dinámico y de integración (cada PR o nightly)

- Suite de autorización: matriz endpoint × rol (§2) + IDOR (§2.3).
- Suite de autenticación: tokens manipulados, expiración, refresh reuse, fail-closed con IdP caído (§1).
- Suite de archivos maliciosos (§5): EICAR, zip-bomb, doble extensión, CSV injection, PDF con JS, path traversal.
- Suite de entrada/salida: mass assignment, headers, CSRF, CORS, error handler (§7).
- Suite de integraciones: respuestas externas malformadas, webhook con firma inválida/replay, SSRF (§4).
- **ZAP baseline scan** contra staging (nightly): High = bloqueo de release.
- Fuzzing ligero de endpoints públicos con `schemathesis` (a partir del OpenAPI): nightly, crashes = bug de seguridad hasta demostrar lo contrario.

### 11.3 Manual/periódico (no automatizable, calendarizado)

- Revisión de lógica de negocio con mentalidad de atacante en cada feature que mueva dinero, permisos o datos entre tenants: ¿puedo aprobarme a mí mismo? ¿doble submit = doble operación (falta idempotency key)? ¿condición de carrera en saldo? Registrar el análisis en el PR (dos líneas bastan; la omisión es el hallazgo).
- Trimestral: revisión de accesos vigentes (usuarios, llaves SSH, tokens CI, miembros del IdP) y de la egress allowlist.
- Anual o ante cambios mayores con datos financieros de clientes: pentest externo. La autoauditoría tiene un techo estructural: no encuentras lo que no sabes buscar.

---

## 12. Respuesta a incidentes (runbooks operativos)

Archivo `INCIDENTES.md` por despliegue, con contactos reales y estos runbooks. Sin plan escrito, la respuesta improvisada llega tarde y destruye evidencia.

**R1 — Credencial/token comprometido:** (1) revocar/rotar el secreto (inventario §3.4 dice cómo); (2) revocar sesiones activas asociadas en el IdP; (3) buscar en logs externos todo uso de la credencial desde la última rotación; (4) evaluar alcance de datos accedidos; (5) si hubo datos personales → R4.

**R2 — Servidor comprometido (o sospecha):** (1) aislar: cerrar entrada en el firewall del proveedor, NO apagar (se pierde memoria/evidencia); (2) snapshot del disco para forense; (3) rotar TODOS los secretos que el servidor conocía (por diseño §3, la KEK de backups y los logs históricos no estaban ahí); (4) reconstruir en servidor limpio desde infra-as-code (§8.4) + restaurar BD desde backup externo verificado; (5) análisis de causa raíz antes de reabrir tráfico; (6) evaluar R4.

**R3 — Archivo malicioso detectado post-ingesta** (pasó el pipeline): (1) identificar por hash SHA-256 (§9.3) qué registros generó; (2) cuarentena de esos datos (flag, no delete); (3) revisar qué usuarios los descargaron; (4) corregir la brecha del pipeline y agregar el caso a la suite §11.2.

**R4 — Brecha de datos personales:** obligaciones de la Ley 21.719 (Chile): notificación a la Agencia de Protección de Datos y, cuando el riesgo lo exige, a los titulares; plazos breves desde el conocimiento del hecho. Mantener registro del incidente, alcance, medidas. (Verificar plazos vigentes del reglamento al redactar el runbook del proyecto; no confiar en memoria.) Si hay datos de clientes de asesoría financiera, evaluar además obligaciones contractuales y de la CMF según el servicio.

**Regla transversal:** durante un incidente se preserva evidencia (logs externos §9.2, snapshots) ANTES de remediar, salvo daño activo en curso.

---

## 13. Estructura de la capa reutilizable y contrato con los proyectos

### 13.1 Repositorios

```
seclib/                     ← librería Python (repo propio, versionado semántico)
  seclib/auth/  authz/  secrets/  crypto/  http/  files/  logging/  middleware/  testing/
  tests/                    ← la suite §11 de la propia lib
infra-base/                 ← plantilla de despliegue (repo propio)
  compose.yml  caddy/  hardening/ (ufw, sshd_config, auditd, unattended-upgrades)
  clamav/  authentik/  backup/  ci/ (workflows con todos los gates §10-§11)
proyecto-X/                 ← cada proyecto
  depende de seclib==X.Y.Z  ← por versión exacta, actualización deliberada
  hereda infra-base         ← y solo sobreescribe config declarada
  SECRETS_INVENTORY.md  INCIDENTES.md  SECURITY_CONFIG.md
```

### 13.2 Contrato de configuración por proyecto (`SECURITY_CONFIG.md` + settings tipadas)

Cada proyecto declara y solo declara: roles y matriz de permisos (§2.2), tipos de archivo aceptados y límites (§5), dominios de egress (§4.4), orígenes CORS (§7.5), campos cifrados (§3.3), retenciones (§9.2), integraciones externas con sus esquemas Pydantic (§4.2). Todo lo demás viene de seclib/infra-base con los defaults de este documento. **Un proyecto que necesita relajar un control lo escribe en `SECURITY_CONFIG.md` con riesgo aceptado y fecha de revisión; sin ese registro, el default manda.**

### 13.3 Instrucción operativa para Claude Code

1. **Al crear la capa:** implementar seclib e infra-base módulo por módulo siguiendo §§1–9, con los tests de "criterios de aceptación" de cada sección escritos ANTES o junto al código del módulo. Un módulo sin sus tests de aceptación no está terminado.
2. **Al crear un proyecto nuevo:** instanciar desde infra-base + seclib; completar el contrato §13.2; correr la suite completa §11; entregar el reporte.
3. **Al auditar un proyecto existente:** reportar por cada ítem DEBE/NUNCA de este documento: CUMPLE / NO CUMPLE / NO APLICA, con archivo:línea y corrección propuesta. Los NO CUMPLE de §§1, 2, 3, 5 y 6 son bloqueantes de despliegue.
4. **Ante ambigüedad:** aplicar §0 — deny by default y fail closed. Si este documento no cubre un caso, la opción restrictiva es la correcta y se anota la brecha del documento para incorporarla.

### 13.4 Límites de este documento (honestidad del alcance)

Esto especifica la capa técnica preventiva + detección básica. NO sustituye: modelado de amenazas específico por proyecto (quién te atacaría y por qué), pruebas de intrusión externas, revisión legal de cumplimiento (21.719 / CMF) para cada servicio concreto, ni la seguridad de TU máquina de desarrollo (que tiene las llaves de todo: disco cifrado, MFA en GitHub/proveedor cloud, y las mismas reglas de higiene de secretos aplican ahí). Esas piezas se agregan por proyecto sobre esta base.

---

*Versión 1.0 — mantener este documento en el repo de seclib; cambios por PR con justificación.*

---

## 14. Especificaciones seclib v2 (Requisitos BudgetFlow)

### 14.1 Emisor JWT y Refresh Token Rotation (R-BF-1)
* **Emisión de Tokens**: El módulo `auth::issuer` es independiente del verificador y genera tokens de acceso (`access`), refresco (`refresh`) y desafío MFA (`mfa_challenge`).
* **Claims Estructurados**: Cada JWT generado DEBE contener las reclamaciones `tenant_id` y `type` (tipo de token). Además, el payload DEBE incluir obligatoriamente los campos `iss` (issuer) y `aud` (audience).
* **Validación Rigurosa**: El proceso de decodificación y verificación de tokens DEBE exigir y validar los campos `iss` y `aud` contra la configuración declarada del emisor.
* **Refresh Token Rotation (RTR)**: Cada token de refresco presentado para rotación es revocado y se emite una nueva pareja (access + refresh).
* **Detección de Reuso (Replay Attack)**: Si se intenta presentar un token de refresco ya marcado como usado/obsoleto, la familia completa de tokens asociada a la sesión DEBE ser inmediatamente revocada de manera fail-closed. Las sesiones activas del usuario asociadas a esa familia quedan invalidadas.

### 14.2 Módulo MFA (TOTP y Códigos de Recuperación) (R-BF-2)
* **Validación de TOTP**: Implementa el algoritmo TOTP (RFC 6238) para la verificación del código de 6 dígitos usando una ventana de tolerancia temporal (`window_steps`) ante desalineación de relojes.
* **Cifrado de Secretos**: Los secretos de TOTP DEBEN ser almacenados cifrados a nivel de base de datos con AES-256-GCM en la jerarquía KEK/DEK, utilizando como associated data (AAD) la convención de tenant-prefixed `{len(tenant)}:{tenant}:{field}`.
* **Códigos de Recuperación**: Los códigos de recuperación generados DEBE ser de un solo uso. Se almacenan de forma segura e irreversible mediante su hash SHA-256 normalizado (sin espacios ni guiones y en minúscula).

### 14.3 Traits de Almacenamiento (SessionStore / RateLimitStore) (R-BF-3)
* **Desacoplamiento**: El almacenamiento de sesiones, tokens de refresco y contadores de rate limit se desacopla del motor físico mediante interfaces/traits (`SessionStore` y `RateLimitStore`).
* **Backends Disponibles**: Se proveen backends basados en (a) memoria para desarrollo y pruebas, (b) PostgreSQL, y (c) Redis (habilitado condicionalmente mediante feature flag). NUNCA depender exclusivamente de Redis si no está configurado.

### 14.4 Rate Limiting por IP e Identidad (R-BF-4)
* **Dimensiones del Límite**: Se impone límite de velocidad tanto por dirección IP como por identidad de usuario (ej. para endpoints críticos como login, MFA, y refresh token exchange).
* **Resistencia a Evasión**: La validación por IP previene botnets de fuerza bruta, mientras que la validación por identidad bloquea el abuso de credenciales distribuidas.
* **Persistencia**: Los contadores de intentos y ventanas de tiempo se almacenan usando las abstracciones de `RateLimitStore`.

### 14.5 OIDC Multi-emisor por Tenant (R-BF-5)
* **Configuración del Servidor**: El resolvedor de OIDC (`TokenVerifier`) determina el emisor (`iss`) y el endpoint de claves JWKS correspondientes en base al inquilino (`tenant_id`).
* **Aislamiento de Emisores**: El mapeo entre `tenant_id` e issuer OIDC es administrado exclusivamente por configuración del servidor. NUNCA se debe resolver el issuer de manera dinámica o confiar en la reclamación `iss` del token no verificado sin validar su pertenencia al tenant.
* **IdP Caído (Fail-Closed)**: Si el servidor de claves JWKS del IdP está caído o devuelve error, la verificación del token aborta con un código `503 Service Unavailable` controlado.

### 14.6 Aislamiento RLS PostgreSQL por Transacción (R-BF-6)
* **Transacción Obligatoria**: La inyección de la variable de tenant para políticas de Row Level Security (RLS) mediante `set_db_session_tenant` DEBE operar obligatoriamente sobre una transacción activa (`&mut Transaction` en Rust, o `Connection` en contexto de transacción en Python).
* **Fail-Closed en Conexiones**: Si no es posible confirmar que la sesión de base de datos tiene una transacción activa, la operación DEBE paniquear o lanzar un error de ejecución inmediato. Esto evita que el contexto del tenant quede almacenado al retornar la conexión al pool (fuga de RLS entre solicitudes).
* **Variable Parametrizada**: El nombre de la variable de sesión (ej. `app.current_tenant` o `app.tenant_id`) se inyecta dinámicamente y se valida sintácticamente contra caracteres extraños para prevenir inyección SQL.

### 14.7 Allowlist de Egress en SecureClient (R-BF-7)
* **Control Saliente**: `SecureClient` permite la configuración de un allowlist de hostnames o IPs confiables (`egress_allowlist`) para conexiones hacia el exterior.
* **Orden de Validación**: El chequeo del allowlist se evalúa estrictamente DESPUÉS de que la IP ha sido resuelta de manera segura y verificada como no privada (protección SSRF/DNS Rebinding). NUNCA saltarse la validación SSRF por estar en el allowlist.

### 14.8 Saneamiento de Celdas CSV (R-BF-8)
* **Función Pública**: Se expone de forma pública y reutilizable la lógica de sanitización de fórmulas en exportaciones CSV.
* **Saneamiento CWE-1236**: Si el texto de entrada de una celda comienza con `=`, `+`, `-`, `@`, tabulador (TAB) o retorno de carro (CR), se le DEBE anteponer un apóstrofo (`'`) para evitar ejecuciones de fórmulas en hojas de cálculo (Excel, Google Sheets). Los números y valores vacíos quedan intactos.

### 14.9 Firma y Verificación Ed25519 (R-BF-9)
* **Criptografía Asimétrica**: Se proveen primitivas de bajo nivel para la firma digital y verificación de firmas utilizando pares de claves Ed25519, posibilitando la validación asimétrica de firmas de auditoría o de licencias en la aplicación cliente.

### 14.10 Límite de Tamaño de Request Body (R-BF-11)
* **Prevención de DoS**: El servidor web impone un middleware de límite de tamaño sobre el request body (`RequestBodyLimitLayer`) para rechazar peticiones con payloads excesivamente grandes de forma fail-closed antes de que agoten la memoria del proceso de la aplicación.

