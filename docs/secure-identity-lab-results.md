# Evidencia ejecutada, 2026-10-30

Checkout base: `cc0f1093a3c9b4576bf7c51f4e503b70ebe0ed2c`.
Rama: `codex/secure-lab-identity`. Host Windows / PowerShell / Rust MSVC.
Esta evidencia se recopiló antes de preparar el commit y la PR; no se hizo merge ni despliegue.
Los archivos previamente staged de `p2p-test` y `test-run` no se modificaron.

| Ejecución | Resultado observado |
| --- | --- |
| `cargo build -p satspathd --bin satspathd` | Éxito |
| `cargo build -p satspath-core --example lab_client` | Éxito |
| `cargo test -p satspath-core --test lab_registration` | 8 passed, 0 failed |
| `cargo test -p satspath-core --test transparency --test transparency_blockers --test adversarial_v2 --test conformance_v2 --test state_map_non_inclusion` | 28 passed, 0 failed (6 + 14 + 4 + 1 + 3) |
| `cargo test -p satspathd --bin satspathd -- --test-threads=1` | 41 passed, 0 failed, 0 ignored |
| `pwsh -NoProfile -File examples/secure-lab-smoke.ps1` y posterior ejecución ampliada con `-SkipBuild` | PASS; autoridad y clientes reales en procesos separados |
| `cargo fmt --all -- --check` | Éxito |
| `git diff --check` | Éxito; sólo avisos de normalización LF/CRLF |

El smoke exportó un descriptor verificado contra el operador local; Alice
registró y firmó en el cliente. Bob resolvió sin token, claves ni acceso a DB.
Luego Charlie añadió el segundo evento y Bob verificó la consistencia desde su
pin de tamaño 1 hasta tamaño 2. La autoridad fue terminada y reiniciada con el
mismo home/origen; Bob volvió a verificar Alice con sus pins anteriores.
Rechazó doble registro, dominio ajeno, solicitud sin bearer, token mock y red
mainnet con lab activado; la conexión falló al terminar la autoridad.

La salida observada distingue `owner_signature`, `log_inclusion` y
`current_state` como `verified_locally`, namespace `explicit_operator_pin`,
`witness_quorum: not_deployed`, `method_ownership: not_verified`,
`environment: synthetic_lab` y `production_payment_ready: false`.

Artefactos del smoke ampliado, conservados fuera del repositorio:
`<TEMP>\satspath-secure-lab-e8ab8bed-e1b7-4c0c-a2b9-8cb0b38a1389`.
Contienen claves de identidad sintéticas de los clientes y la clave del operador
de esta prueba; no publicar el directorio ni confundirlo con datos de producción.

## Límites de la evidencia

- Los primeros intentos dentro del sandbox fallaron con Access denied al
  renombrar archivos temporales; Windows también bloqueó un ejecutable de tests
  con Application Control. La repetición autorizada fuera del sandbox pasó.
- Hubo un bloqueo del linker por un ejecutable de tests retenido y una expectativa
  errónea de test que esperaba otro código HTTP; se detuvo esa ejecución, se
  corrigió la expectativa y la suite completa pasó sin excluir tests.
- El smoke detectó que el helper HTTP existente preservaba status 200 incluso en
  error. Los endpoints lab ahora devuelven 400 ante rechazo y el cliente exige
  `status: registered`; la ejecución final pasó.
- La compilación del daemon informa dos warnings dead_code por conservar las
  estructuras wire de verify/claim legacy que ahora se rechazan. Hubo avisos
  adicionales de hardlink/incremental en OneDrive. No se afirma Clippy limpio.
- No se ejecutó `cargo test --workspace`, CI remoto, auditoría externa, pagos,
  DNSSEC de dominio real, witnesses de operadores independientes ni Hyperswarm DHT.
- Los tests de vectores existentes tienen límites propios (incluyen un vector
  dummy omitido internamente); no son certificación criptográfica interlenguaje.
- El test de almacenamiento usa un trigger SQLite que aborta el insert del
  checkpoint: demuestra rollback transaccional, no durabilidad ante todos los
  fallos físicos de disco o caída de energía.

El informe de arquitectura, comandos Ubuntu/Windows, decisiones, incompatibilidades
deliberadas y tareas de seguimiento está en [secure-identity-lab.md](secure-identity-lab.md).
