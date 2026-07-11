# seclib (Rust)

Capa de seguridad transversal (Transversal Security Layer) para aplicaciones
backend. Este repositorio es el **puerto en Rust** de seclib: un núcleo de
seguridad reutilizable, sus enlaces para Python y un servidor de referencia.

## Estructura del workspace

| Ruta | Crate | Rol |
|------|-------|-----|
| `crates/seclib-core` | `seclib-core` | Núcleo de la librería (lógica de seguridad). |
| `bindings/seclib-py` | `seclib-py` | Enlaces PyO3 (`cdylib`) para consumir el núcleo desde Python. |
| `server/seclib-server` | `seclib-server` | Servidor de referencia (axum). |

## Postura de seguridad

- `#![forbid(unsafe_code)]` a nivel de crate: no se admite código `unsafe`.
- Lints estrictos denegados como error: `unwrap_used`, `expect_used`, `panic`,
  `todo`, `unimplemented`, `dbg_macro`.
- MSRV: Rust **1.88**.
- CI con gates obligatorios: `rustfmt`, `clippy` (release y con tests, ambos
  `-D warnings`), `cargo-deny`, `cargo-machete`, detección de secretos y la
  suite de tests (incluye prueba de aislamiento RLS contra PostgreSQL).

## Uso como dependencia

Fijar por tag para builds reproducibles:

```toml
[dependencies]
seclib-core = { git = "https://github.com/jriveros64/seclib-rust", tag = "seclib-rs-v2.0.5" }
```

## Repositorio público

Este código es público **para transparencia y evaluación de seguridad por
terceros** (análisis estático, revisión, fuzzing). La visibilidad no compromete
la seguridad: esta no depende del secreto del código, sino de las claves y
secretos de despliegue, que no se versionan aquí.

## Licencia

Distribuido bajo la **Licencia Apache, Versión 2.0**. Ver [LICENSE.md](LICENSE.md)
y [NOTICE](NOTICE).

Copyright 2026 jriveros64.
