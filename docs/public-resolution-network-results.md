# Resultados ejecutados: public resolution network

2026-10-30. Rama `feat/public-resolution-network`; base Git
`cc0f1093a3c9b4576bf7c51f4e503b70ebe0ed2c`, más los cambios de identidad segura
sin commit de la etapa anterior. Se preservaron los archivos previamente staged
de `p2p-test` y `test-run`. La evidencia se recopiló antes de preparar el commit y la PR. No se hizo merge ni despliegue público.

## Tests y compilación

| Ejecución | Resultado real |
| --- | --- |
| `cargo test -p satspath-core --test lab_registration` | 8 passed, 0 failed |
| `cargo test -p satspath-core --test verified_replication` | 7 passed, 0 failed |
| `cargo test -p satspath-core --test transparency --test transparency_blockers --test adversarial_v2 --test conformance_v2 --test state_map_non_inclusion` | 28 passed: 6 + 14 + 4 + 1 + 3 |
| `cargo test -p satspath-witness --test witness_quorum` | 3 passed, 0 failed |
| `cargo test -p satspathd --bin satspathd -- --test-threads=1` | 41 passed, 0 failed, 0 ignored |
| `npm.cmd test` en `sdk/satspath-p2p` | 20 passed, 0 failed, 0 skipped |
| Total de esas suites | **87 Rust + 20 Node**, sin sumar reintentos como tests nuevos |
| Compilación daemon/cliente MSVC | Éxito; dos warnings dead_code de tipos wire legacy conservados |
| Compilación daemon/cliente Linux en Docker | Éxito con Rust 1.99 y el lockfile local |
| `cargo fmt --all -- --check` | Éxito |
| `git diff --check` | Éxito; avisos de normalización LF/CRLF |

Las siete pruebas nuevas de réplica cubren: almacenamiento/reinicio/frescura y
continuidad C; rollback/fork/clave/destino/corrupción; fallo tardío transaccional y
cuarentena persistente; cross-binding de alias; 1.000 endpoints Sybil;
quorum 2-of-3, pérdida de witnesses, 1.000 firmas Sybil/no autorizadas, duplicados
y distintas representaciones de una clave; y HTTP failover sólo por disponibilidad,
sin fallback después de evidencia criptográfica inválida.

No se ejecutó toda la workspace ni se afirma un pase de Clippy/CI/auditoría externa.
Los vectores de conformance heredados contienen un vector dummy omitido
internamente; ese detalle no es evidencia criptográfica adicional.

## A/B/C entre procesos

`pwsh -NoProfile -File examples/secure-lab-smoke.ps1 -Federation` pasó inicialmente
con procesos Windows separados: registro, firma de Alice, pull verificado por B,
pin de C en tamaño 1, update autorizado, sincronización a tamaño 2, A apagada,
verificación independiente desde B, reinicio de B sin claves y rechazo al caer
todos los endpoints.

Artefactos de esa ejecución:
`<TEMP>\satspath-secure-lab-a98af645-e851-4fc0-8cf2-611f940e2513`.
Es un home de laboratorio con **claves sintéticas privadas**: no publicarlo.

Una recompilación Windows posterior produjo un cliente que Application Control
impidió arrancar. No se contó ese reintento como éxito ni se desactivó la política.
La ejecución final del flujo se verificó con los binarios Linux compilados del
mismo código en contenedores.

## A/B/C en contenedores Linux independientes

Comando aprobado y ejecutado:

```powershell
pwsh -NoProfile -File examples/public-resolution-containers.ps1
```

Proyecto final: **`satspath-lab-d01f643b`**.
Imagen construida: **`satspath-lab-d01f643b:local`**.

Resultado: **PASS**.

1. A registró Alice y sirvió secuencia 0 / checkpoint 1.
2. B sincronizó/verificó en su volumen propio; C guardó su propio pin.
3. El cliente Alice firmó el cambio de destino y A confirmó secuencia 1 / checkpoint 2.
4. B verificó el avance antes del apagado de A.
5. C, con pin anterior, obtuvo de B el perfil actualizado y verificó consistencia.
6. B reinició con A apagada y C volvió a resolver el perfil firmado.
7. Al apagar B también, C falló con `all authorized resolution endpoints unavailable`.

Salida de C tras apagar A (campos relevantes):

```json
{
  "identifier": "alice@lab.satspath.test",
  "served_by": "http://127.0.0.1:9738",
  "profile_sequence": 1,
  "tree_size": 2,
  "owner_signature": "verified_locally",
  "log_inclusion": "verified_locally",
  "current_state": "verified_locally",
  "max_checkpoint_age_seconds": 300,
  "trust_status": "degraded_unwitnessed_lab",
  "witness_quorum": "not_deployed",
  "method_ownership": "not_verified",
  "production_payment_ready": false
}
```

A, B y C tienen contenedores y estados separados. Comparten explícitamente un
namespace de red loopback para el HTTP lab; no se presenta como una prueba de
TLS, NAT o disponibilidad entre datacenters. Sólo A monta su volumen privado;
exporta el descriptor dentro de A. B/C montan el descriptor público read-only.
Los contenedores de cada ejecución final se retiraron; los volúmenes e imágenes
se conservaron para auditoría. Docker Desktop quedó iniciado; no se detuvieron
contenedores ajenos a esta tarea.

Evidencia pública exportada, sin tokens ni claves:
`<TEMP>\satspath-container-evidence-satspath-lab-d01f643b`.

## Experimento Hyperswarm separado

Primero se ejecutaron publisher y resolver existentes en dos procesos Node,
obteniendo un perfil que el cliente Rust verificó contra la evidencia S2S.
Después se ejecutó la prueba automatizada:

```powershell
pwsh -NoProfile -File examples/hyperswarm-lab-smoke.ps1 `
  -Artifacts '<TEMP>\satspath-container-evidence-satspath-lab-00f9c0d1' `
  -ClientImage 'satspath-lab-00f9c0d1:local'
```

Resultado final: **PASS**. El publisher confirmó `Waiting for peers`, el resolver
informó `Peer connected`, guardó un candidato y Rust comprobó igualdad con el
perfil comprometido y todas las evidencias S2S. Alterar el destino produjo
`transport profile differs from authenticated S2S state`, rechazo esperado.
La verificación se realizó en un contenedor sin red y con archivos públicos
read-only; el descubrimiento/transporte fue Hyperswarm real en dos procesos Node.

Artefactos públicos del experimento:
`...\satspath-container-evidence-satspath-lab-00f9c0d1\hyperswarm-b49ea24c-28ee-4e4a-8ebd-d58860101996`.

Un intento automático anterior agotó discovery sin candidato. Se corrigió el
harness para esperar confirmación de anuncio antes de iniciar el resolver. No
se contó ese timeout como éxito, ni se modificó/reimplementó Hyperswarm. Sigue
siendo experimental y esta prueba no certifica conectividad entre redes distintas.

## Incidencias corregidas y límites

- El sandbox produjo EACCES en TCP y renombrados; las suites autorizadas fuera del
  sandbox pasaron. Hubo bloqueos intermitentes Application Control al arrancar
  ejecutables recién generados; los reintentos bloqueados nunca ejecutaron tests.
- Docker no estaba iniciado. Se inició Docker Desktop para el laboratorio local.
  Una consulta adicional de BuildKit no llegó a ejecutarse porque la revisión
  automática de permisos agotó su plazo; no fue un rechazo por riesgo. La
  construcción se repitió con salida visible y luego pasó.
- El primer bootstrap en contenedor con el volumen privado de A montado read-only
  falló por metadatos de SQLite WAL. Se trasladó el bootstrap a A, manteniendo
  su estado privado fuera de B/C. La ejecución completa posterior pasó.
- No hay quorum de operadores desplegados, gossip, descubrimiento DNSSEC público,
  hosted real, migración/rotación de autoridad automática, proofs arbitrarios de
  backfill, prueba física de power loss, benchmark multiusuario ni pago real.
- La réplica es de envelopes para alias configurados, no un full mirror de todas
  las entradas/namespaces. Caduca a los 300 segundos de edad de checkpoint y no
  crea latidos firmados para prolongar disponibilidad.
- Un operador confiado puede bifurcar la primera vista de un cliente nuevo sin
  quorum real; las simulaciones Sybil prueban allowlists/firmas/pins, no una
  defensa global de Internet.

## Archivos de esta etapa

- Core: `src/transparency/replication.rs`, `database.rs`, `protocol.rs`,
  `resolver.rs`, `log.rs`, `verifier.rs`, `mod.rs`; se reutiliza `src/lab.rs`.
- Cliente: `crates/satspath-core/examples/lab_client.rs`.
- Tests: `crates/satspath-core/tests/verified_replication.rs`, fixture compartido
  `tests/support/lab_fixture.rs` y adaptación de `tests/lab_registration.rs`.
- Daemon: `src/replica.rs`, `config.rs`, `main.rs`, `router.rs`,
  `handlers/lab.rs`, `handlers/transparency.rs`.
- Witness: `crates/satspath-witness/src/lib.rs` y `tests/witness_quorum.rs`;
  deduplicación compartida por identidad BIP340 x-only, incluyendo P/-P.
- Docker: `docker/public-resolution.Dockerfile`, su `.dockerignore` específico
  y `docker/public-resolution.compose.yml`.
- Scripts: `examples/secure-lab-smoke.ps1`, `public-resolution-containers.ps1`,
  `hyperswarm-lab-smoke.ps1`.
- Documentación: este informe y [arquitectura/comandos/riesgos/milestones](public-resolution-network.md).

El diff total incluye también los cambios de identidad segura de la etapa previa,
que ya estaban sin commit al iniciar esta solicitud.
