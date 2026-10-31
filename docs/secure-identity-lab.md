# Identidades verificables: auditoría y primer laboratorio seguro

Fecha: 2026-10-30. Rama: `codex/secure-lab-identity`.
Este documento describe este checkout y sus cambios, no certifica producción.

## Hallazgos y reutilización

| Componente inspeccionado | Estado encontrado | Decisión |
| --- | --- | --- |
| `satspath-core` / `SignedPaymentProfile` | Firmas Schnorr, canonicalización, comprobación de material privado, expiración y proofs de métodos existentes | Reutilizar; no generar ni recibir claves de gasto |
| `NameEvent` | Registro, actualización, rotación con ambas claves y revocación; secuencia y predecessor; recuperación rechazada | Reutilizar sin inventar lifecycle alternativo |
| SQLite `TransactionalTransparencyStore` | Perfil, eventos, checkpoint y operator state en una transacción; comparación del prefix frente a escritores concurrentes; replay al abrir | Extender con reservas y consumo atómico |
| Merkle / sparse state map | Inclusión, consistencia y estado actual autenticado; reconstrucción desde eventos | Reutilizar, sin blockchain nueva |
| Daemon challenge/verify | Mock que aceptaba el alias como token; sin control de namespace, red ni challenge de un uso | Deshabilitar ese protocolo inseguro; nuevo endpoint lab con posesión criptográfica |
| Claims | Un invite no autoriza el dominio; el handler podía publicar el alias del receptor | Rechazar publicación antes de mutaciones hasta integrar onboarding autorizado |
| S2S `/v2/resolve` | Envelope, historial, inclusión y prueba de estado; sin witnesses ni consistencia inline | Cliente verifica todo localmente y consulta la consistencia existente si necesita crecimiento |
| `NamespaceDescriptor` | Handler devolvía firma vacía y tomaba la clave de wallet; `verify_namespace_binding` sólo validaba campos | Firmar con operador del laboratorio; cliente usa firma y pin externo. El helper legacy ahora rechaza firmas inválidas y devuelve Skipped sin ancla externa |
| DNSSEC y HTTPS | Parser `DnsDescriptor`; BIP353/resolver HTTPS existentes; CLI `dns check`, `identity` y `server` con placeholders | No anunciar descubrimiento automático S2S como implementado |
| Hyperswarm | Bridge opcional con `--p2p`, supervisión Node, intercambio de perfiles, validación Rust de candidatos y pins locales | Mantener experimental; candidato P2P no acredita autoridad del namespace |
| E2E | Tests de firmas, rotación, rollback, SMT, almacenamiento y HTTP; algunos sólo Unix o externos | Reutilizar y añadir adversariales lab y smoke entre procesos |

Se revisaron `docs/s2s/protocol-v2.md`, `trust-model-v2.md`,
`dns-delegation-v2.md`, `wire_p2p.md`, `satspathd_hyperswarm.md`, ownership,
registry, claims, API v2, resolvers y persistencia. `docs/README.md` y
`docs/API_REFERENCE.md` no existen en esta rama.

Se consultaron [#201](https://github.com/satspath/satspath/issues/201),
[#206](https://github.com/satspath/satspath/issues/206) y los issues S2S
[#47](https://github.com/satspath/satspath/issues/47),
[#49](https://github.com/satspath/satspath/issues/49),
[#51](https://github.com/satspath/satspath/issues/51),
[#52](https://github.com/satspath/satspath/issues/52),
[#53](https://github.com/satspath/satspath/issues/53),
[#54](https://github.com/satspath/satspath/issues/54),
[#58](https://github.com/satspath/satspath/issues/58).
**Trabajo existente fuera de este checkout:** el comentario de #201 referencia
[PR #215](https://github.com/satspath/satspath/pull/215), abierta al consultar,
con challenges HTTPS temporales, claims y persistencia más avanzados.
No se importó ni se hizo merge de esa PR. Antes de ampliar onboarding de
producción hay que reconciliar/reutilizar esa implementación; este slice
no implementa un protocolo de delegación HTTPS competidor.

## Alcance y amenazas

Sólo se admite `local-part@lab.satspath.test`, en minúsculas ASCII, con
`local-part` de 1..64 caracteres `[a-z0-9._-]`. La red debe ser exactamente
`regtest` o `devnet` y `SATSPATH_ENABLE_LAB_REGISTRATION=1`.
Mainnet, testnet, signet, dominios externos y hosted reales son rechazados.
El mock de correo queda compilado sólo en unit tests; no está disponible en
el daemon. La habilitación explícita activa el laboratorio criptográfico,
no los viejos tokens mock.

Las cuatro autorizaciones son distintas:

1. **Namespace:** descriptor de laboratorio firmado y transferido por un canal
   autenticado. No demuestra propiedad DNS ni posesión de `satspath.com`.
2. **Admisión:** el operador autenticado con el bearer administrativo asigna un
   nombre disponible a una clave concreta. En la API core se exige además una
   aprobación firmada por la clave que el integrador confía como autoridad.
   Nunca se entrega el token administrativo a usuarios hosted.
3. **Posesión:** Alice firma el challenge, perfil y evento en su propio proceso.
   El servidor recibe únicamente material público.
4. **Métodos:** una dirección Lightning firmada por Alice sigue siendo una
   afirmación de Alice. La propiedad de esa dirección exige los proofs
   independientes ya existentes. No se produce una autorización de pago.

`POST /v1/lab/registrations/reserve` recibe `{alias, identity_pubkey}`. Ambos
endpoints nuevos requieren el bearer del operador. La reserva genera un nonce
aleatorio y una expiración de cinco minutos, vinculados también a namespace,
log, autoridad, operación y clave. SQLite impone una reserva única por alias.
La solicitud autorizada de un nombre ocupado falla; no renueva reservas activas.
Una reserva no consumida caducada puede reemplazarse. Las consumidas se conservan.

`POST /v1/lab/registrations/complete` recibe challenge, firma de posesión,
`signed_profile` y `event`. El perfil debe tener expiración futura. El evento
debe ser Register de secuencia cero y estar firmado por el propietario.
El daemon prepara su checkpoint. SQLite consume el challenge junto con el
perfil, evento, checkpoint y operator state. Un fallo tardío revierte todo.
El mapa de estado se reconstruye determinísticamente de los eventos y su raíz
queda comprometida en el checkpoint. La confirmación rechaza replay, sustitución
de challenge, perfil, clave, autoridad, expiry y escrituras concurrentes.
Un registro inicial de este namespace mediante la API genérica de persistencia
es rechazado; las transiciones posteriores conservan el lifecycle existente.

El challenge prueba aceptación del binding nombre/clave; las firmas independientes
del perfil y evento autorizan su contenido exacto. No se acepta una firma del
challenge en lugar de esas firmas.

## Confianza remota

Bob usa un descriptor exportado en la máquina de la autoridad, comprobado contra
la clave pública derivada de `transparency/operator.key` y el log local. Sólo se
transfiere el descriptor público a Bob. Descargar un descriptor de un servidor
arbitrario y llamarlo confiable no es bootstrap seguro.

El cliente toma el origen del descriptor, sin introducir la IP del receptor
ni usar SSH. Permite HTTPS, o HTTP sólo en loopback para pruebas locales.
Deshabilita redirects y proxies, limita cada respuesta a 64 KiB y el request a
cinco segundos. Exige igualdad de dominio, log, clave, endpoints y witness policy
frente al pin; verifica firma y vigencia del descriptor, perfil, eventos,
checkpoint, inclusión, SMT y el binding del estado a la cabeza actual. Exige
checkpoint de menos de cinco minutos y guarda un pin local tras verificar.
Un checkpoint que crece requiere la prueba de consistencia existente; rollback
y conflictos fallan. No confía en `signature_valid` remoto.

El hashing público de identificadores aún usa el helper legacy dependiente de
`SATSPATH_PEPPER`. Este demo usa el valor dev conocido en ambos procesos. Una
configuración distinta causa rechazo de los bindings; no compartir un pepper
secreto con Bob para resolverlo. Separar hashing público S2S de privacidad local
requiere una migración de formato/versionado antes de producción.

El estado muestra `synthetic_lab`, `explicit_operator_pin`, ausencia de quorum,
métodos no verificados y `production_payment_ready: false`. Los quotes del daemon
rechazan identidades sin atestación y siempre rechazan este namespace sintético.
No existe protección global contra split view con quorum cero. El operador
todavía controla primera asignación, disponibilidad y presentación de forks a
clientes nuevos. Una firma propia del descriptor no crea autoridad sobre DNS.
Descriptor y perfil caducan tras una hora; el demo no incluye renovación.

## Persistencia y compatibilidad

SQLite WAL es suficiente para este primer servicio local de un escritor.
No hay evidencia de carga que justifique PostgreSQL. Se añade una tabla sin
borrar ni convertir perfiles existentes. Conservar backups consistentes mediante
SQLite backup API, no copiando sólo el `.sqlite3` mientras exista WAL activo.

La comprobación del prefix y checkpoint anterior bajo `BEGIN IMMEDIATE` rechaza
carreras; la aplicación puede reintentar desde estado fresco. Una respuesta de
red perdida tras commit no revierte un registro: resolver y verificar antes de
reintentar; el replay no crea otro evento. No se promete respuesta idempotente
de confirmación todavía.

Si métricas futuras justifican PostgreSQL: extraer interfaz transaccional,
mantener adaptador SQLite, añadir unicidad `(namespace, canonical_local_part)`,
bloquear cabeza de log y challenge en la misma transacción, ejecutar los mismos
tests de fallos/concurrencia, importar snapshot validado y comparar raíces y
checkpoints antes de cambiar lectura/escritura. No usar dual writes sin outbox
transaccional ni inventar durabilidad a través de dos commits independientes.

**Cambio de compatibilidad deliberado:** challenge/verify mock, publicación de
claims y mutaciones HTTP de wallet antiguas fallan cerradas. No migran silenciosamente
identidades anteriores a identidades autorizadas. Lecturas y primitivas de firmas,
actualización/rotación/revocación permanecen; el nuevo registro mantiene las claves
de usuarios fuera de la wallet del operador. La UI antigua no implementa el nuevo
flujo: usar el cliente de laboratorio. Esta etapa no es un reemplazo de la PR #215.

## Configuración y ejecución reproducible

Prerequisitos: Rust/Cargo y compilador nativo; PowerShell 7 para el smoke portable.
No Bitcoin Core, Node, wallet externa ni Hyperswarm son necesarios.

Windows y Ubuntu con PowerShell 7, desde la raíz:

```powershell
pwsh -File examples/secure-lab-smoke.ps1
```

El script compila daemon y cliente, usa hogares temporales nuevos, ejecuta Alice y
Bob en procesos separados, niega duplicados, dominios externos, ausencia de auth,
tokens legacy y mainnet incluso con lab activado; comprueba que la caída de la
autoridad falla. Sólo finaliza procesos creados por el script y conserva artefactos
para inspección. En Windows ejecutar en una carpeta con ACL privada al usuario;
en Unix el cliente crea su clave de identidad con modo 0600. Es una clave del
protocolo, nunca una seed ni clave privada de gasto.

Ubuntu sin PowerShell, terminal de autoridad:

```bash
cargo build -p satspathd --bin satspathd
cargo build -p satspath-core --example lab_client
umask 077
export SATSPATHD_AUTH_TOKEN="$(openssl rand -hex 32)"
export SATSPATH_ENABLE_LAB_REGISTRATION=1
export SATSPATH_AUTHORITY_URL=http://127.0.0.1:9737
target/debug/satspathd --network regtest --home ./lab-authority --bind 127.0.0.1:9737 --no-open
```

En otra terminal con el mismo token **sólo para el operador que registra Alice**:

```bash
target/debug/examples/lab_client bootstrap ./lab-authority http://127.0.0.1:9737 ./trusted-lab.json
target/debug/examples/lab_client register ./trusted-lab.json ./lab-alice alice@lab.satspath.test alice@example.com
unset SATSPATHD_AUTH_TOKEN
target/debug/examples/lab_client resolve ./trusted-lab.json ./lab-bob alice@lab.satspath.test
```

Windows manual equivalente: configurar `$env:SATSPATHD_AUTH_TOKEN` con 64 dígitos
hex aleatorios y `$env:SATSPATH_ENABLE_LAB_REGISTRATION='1'`; ejecutar los mismos
argumentos con `target/debug/satspathd.exe` y
`target/debug/examples/lab_client.exe`. Para Bob,
`Remove-Item Env:SATSPATHD_AUTH_TOKEN -ErrorAction SilentlyContinue`.

Dos máquinas: publicar el daemon detrás de un HTTPS con certificado válido,
configurar `SATSPATH_AUTHORITY_URL=https://<autoridad-del-lab>` y los controles
TLS/host existentes; exportar pin en A y transferir **sólo JSON público** por canal
autenticado a B. El cliente B no recibe la base de datos, token ni claves de A.
La prueba ejecutada aquí es entre procesos Windows sobre loopback, no certifica
TLS público ni un despliegue en dos máquinas.

```bash
cargo test -p satspath-core --test lab_registration
cargo test -p satspath-core --test transparency --test transparency_blockers --test adversarial_v2 --test conformance_v2 --test state_map_non_inclusion
cargo test -p satspathd --bin satspathd -- --test-threads=1
cargo fmt --all -- --check
```

## Delegación externa propuesta: reutilizar S2S v2

Mantener `_satspath.<domain>` TXT `v=sp2; e=...; k=...; l=...; w=...` y
`https://<domain>/.well-known/satspath-authority`. El responsable del dominio
publica la autorización temporal; el servidor propuesto no puede autorizarse a
sí mismo. Una autorización debe vincular dominio exacto, descriptor firmado,
log/operador, política de witnesses, intervalo temporal y continuidad de versión.

DNSSEC debe validar localmente cadena, RRSIG, DS/DNSKEY y delegaciones; limitar
cache por TTL y validez firmada, rechazar bogus/ambiguos/duplicados y rollback,
sin fallback HTTPS silencioso tras fallo DNSSEC. HTTPS debe usar el origen del
dominio original, WebPKI válido, sin redirects, con límites/SSRF, descriptor
firmado y expiración. Es una confianza WebPKI distinta de DNSSEC; acceso a un
correo no autoriza el dominio. Reutilizar el fetch/verificación temporal de PR
#215 una vez reconciliada, en lugar de crear otra verificación HTTPS.

[BIP353](https://bips.dev/353/) publica instrucciones `bitcoin:` en
`user.user._bitcoin-payment.domain`, requiere validación DNSSEC independiente
y no define el formato de namespace SatsPath. No sobrecargar esos registros
con un segundo descriptor incompatible. [RFC4035](https://www.rfc-editor.org/info/rfc4035/)
es la base de validación DNSSEC. El parser actual y el flag AD recibido por sí
solos no completan estas garantías. **Registro externo deshabilitado.**

## Bloqueos y seguimiento

No están entregados: hosted público, autorización real de `satspath.com`, DNSSEC
S2S completo, discovery automático, scopes multiusuario, renovación de perfiles,
API remota de actualización/rotación/revocación, recuperación, quorum independiente,
replicación integrada, revisión criptográfica independiente, prueba TLS en dos
máquinas ni pago real. Los tests de rotación y revocación reutilizan las primitivas
existentes; recuperación sigue siendo un rechazo explícito y seguro.

Tareas locales, enlazadas a trabajo existente (no se crearon issues duplicados):

- #201 / PR #215: reconciliar migraciones/challenges/claims y desactivar rutas
  antiguas de forma compatible antes de ampliar hosted.
- #49: validación local DNSSEC y continuidad de descriptor; probar cadena bogus,
  expiry, delegaciones y rollback; HTTPS no puede promocionarse a DNSSEC.
- #54: firma offline, mutaciones remotas, autorización por usuario e idempotencia
  sin repartir el token de operador; pruebas de rotación/revocación entre procesos.
- #206 / #51 / #53: witnesses independientes, consumo de quorum, réplicas,
  consistencia inline y readiness honesta. El health actual no certifica quorum.
- #48: vectores interlenguaje de firma de descriptor y esquema estricto completo;
  el helper sin ancla devuelve Skipped, y nunca debe promoverse a autoridad DNS.
  Versionar hashing público independiente del pepper privado local.
- #58: prueba Hyperswarm independiente: dos instalaciones SDK/Node, publicar perfil
  firmado, descubrir desde proceso separado, rechazar alias/clave alterados, expiry
  y conflicto con pin, mantener indicador de autoridad no verificada. No se ejecutó
  DHT/Hyperswarm aquí ni se reescribió el transporte.
- Persistencia: crash real/kill durante commit, disco lleno/IO real y backups;
  el test actual inyecta un fallo SQLite tardío, no simula todos los fallos físicos.

Los resultados ejecutados se registran en `secure-identity-lab-results.md`.
