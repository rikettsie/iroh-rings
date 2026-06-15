# Changelog

All notable changes to this project will be documented in this file.

## [0.7.0] - 2026-06-15

### Documentation

- (**security**) Add deps.rs badge in README

### Refactoring

- (**deps**) Major dependency update (iroh, iroh-blobs, etc)

## [0.6.1] - 2026-05-31

### Documentation

- Add threat model and architecture diagram

## [0.6.0] - 2026-05-26

### Features

- (**examples**) Add more granular use cases on Read, Write, Delete
- (**backends/redb**) Migrate nicknames table to labels (schema v1→v2)

### Refactoring

- (**registry**) Rename nickname to label in trait and tests
- (**backends**) Rename nickname to label in both backends

## [0.5.0] - 2026-05-24

### Bug Fixes

- (**fs**) Grant access for directly tagged blobs in FsTransfer::can_access
- (**gate**) Use || so collection sub-blobs are accessible via can_access

### Documentation

- Inline ALPN re-export so it appears under Constants at crate root
- Document the permission model across registry, redb, and crate root
- Update README with new permission semantics

### Features

- (**registry**) Add Permission enum with Read, Write, and Delete variants
- (**registry**) Extend ring–resource associations with per-ring permission sets
- (**protocol**) Bump ALPN to /iroh-rings/2 and add operation byte to wire format
- (**registry**) Restrict open ring to Read-only permission
- Allow open ring and private rings to coexist on a resource
- (**examples**) Add minimal working example covering ring access
- (**Redb**) Add migration backfilling resource ring permissions

### Refactoring

- Extract validation, fix permission corruption, optimize has_permission

## [0.4.0] - 2026-05-22

### Refactoring

- (**protocol**) Reexport ALPN name according to iroh ecosystem

## [0.3.0] - 2026-05-20

### Features

- Replace anyhow with typed Error across public API
- Replace anyhow with typed Error across public API

### Refactoring

- Harden public API surface (field privacy, non_exhaustive, docs, tracing)

## [0.2.0] - 2026-05-18

### Bug Fixes

- (**gate**) Parse generic ResourceId size in handle_request()
- (**protocol**) Reflect generic resource id length support on wire protocol

### Documentation

- Add more docs on the security/threat model
- Update README with new protocol breaking change

### Features

- Bump new /iroh-rings/1 protocol ver with max ResourceId size

### Refactoring

- (**fs**) Enforce named constants for wire BAO ranges

## [0.1.3] - 2026-05-17

### Documentation

- Polish documentation

### Miscellaneous Tasks

- Add CHANGELOG updates to Github release

## [0.1.2] - 2026-05-12

### Documentation

- Improve documentation across modules

### Miscellaneous Tasks

- Activated OIDC publishing on crates.io

## [0.1.1] - 2026-05-12

### Documentation

- Add README.md

### Features

- Extract iroh-rings as a standalone access-control library

### Miscellaneous Tasks

- Add Github workflows for tests and publish
- Temporarily switched to static crates.io access token


