# Phase 4 plan — Windows SSPI

**Branch (when implemented):** `feat/042-phase4-winsspi`
**Date:** 2026-05-13
**Status:** Plan — design doc only; no code yet.
**Depends on:** PRs #7 (Linux build fix), #8 (warning fix), #9 (security follow-up)
  merged to `main`. Phase 4 builds on a clean post-ultrareview baseline.

## Context

Spec 042 Phases 1-3 shipped POSIX Kerberos integrated authentication via
system GSSAPI. Windows users currently see an explicit "Phase 4 not yet
implemented" error from `auth_strategy_factory.cpp` when they specify
`Trusted_Connection=yes` or `authenticator=winsspi`. The interim workaround
documented in `Kerberos.md` is WSL2 Ubuntu (which works because WSL2 is a
real Linux kernel with MIT Kerberos).

Phase 4 completes the spec by adding `WinSspiAuthenticator` — the Windows
equivalent of `Krb5Authenticator`, using `secur32.dll`'s `Negotiate` security
package instead of GSSAPI. The end-to-end goal:

```sql
-- On a domain-joined Windows host, no kinit needed (uses logon session):
ATTACH 'Server=sqlhost.corp.example.com;Database=YourDB;Trusted_Connection=yes;Encrypt=yes;TrustServerCertificate=yes'
    AS db (TYPE mssql);
```

## Scope

| In | Out (deferred) |
|---|---|
| `WinSspiAuthenticator` implementing `IAuthenticator` via `secur32.dll` Negotiate package | NTLM-only servers (we negotiate SPNEGO; if KDC isn't reachable Negotiate falls back to NTLM — that path is OS-managed, not ours) |
| Single credential mode: current Windows logon session (`SECPKG_CRED_OUTBOUND` with `NULL` auth data) | Keytab mode on Windows (there is no Windows analog; service accounts use SCM-managed credentials) |
| SPN derivation identical to POSIX path (`MSSQLSvc/<fqdn>:<port>`, or `service_principal_name` override) | Channel binding / Extended Protection for Authentication (`ATTR_PROTOCOL`, `ATTR_BINDINGS`) — v2 |
| Error mapping via `FormatMessageW` mirror of the `HintForMinor` taxonomy on POSIX | Constrained delegation (S4U2Self/S4U2Proxy) — v2 |
| Windows CI workflow_dispatch verification of build + parser tests | Cross-realm trust corner cases — v2 |
| Update `Kerberos.md` Windows section: replace "Phase 4 not yet shipped" with the real instructions | |

## Architectural fit

`WinSspiAuthenticator` is a peer of `Krb5Authenticator`. Both implement
`IAuthenticator` (`InitialBytes` / `NextBytes` / `Free`). The
`AuthStrategyFactory::Create()` already has a stub branch that throws
"Phase 4 not yet implemented"; this work replaces that stub with a real
`WinSspiAuthenticator` construction, wrapped in the existing
`IntegratedAuthStrategy` adapter. The SPNEGO continuation loop in
`TdsConnection::AuthenticateIntegrated()` works unchanged — it just calls
into a different `IAuthenticator` implementation.

```
TdsConnection::AuthenticateIntegrated(...)
        │
        ▼  IAuthenticator (existing interface, no changes)
        │
        ├── Krb5Authenticator       (POSIX, shipped Phase 3)
        └── WinSspiAuthenticator    (Windows, THIS PHASE)
```

No changes to:
- LOGIN7 packet builder (`BuildLogin7WithSSPI`)
- TDS `0xED` token parser
- `IntegratedAuthStrategy` adapter
- Connection-string parser
- ATTACH plumbing / pool factory

## SSPI ↔ GSSAPI call mapping

Direct mirror of `Krb5Authenticator::InitialBytes` / `NextBytes` / `Free`.
Reference: Microsoft Learn "SSPI/Kerberos Interoperability with GSSAPI"
(canonical call-by-call table).

| Concept | GSSAPI (Phase 3) | Windows SSPI (Phase 4) |
|---|---|---|
| Acquire creds | `gss_acquire_cred(GSS_C_NO_NAME, ...)` (default) | `AcquireCredentialsHandleW(NULL, L"Negotiate", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &cred, &expiry)` |
| Import target name | `gss_import_name(spn, GSS_C_NT_HOSTBASED_SERVICE)` | Pass SPN as the `pszTargetName` parameter to `InitializeSecurityContextW` |
| Initial / continuation | `gss_init_sec_context(..., input_token, &output_token, &ret_flags, &time_rec)` | `InitializeSecurityContextW(&cred, &ctx, target, ISC_REQ_*, 0, SECURITY_NATIVE_DREP, in_buf_desc, 0, &ctx, out_buf_desc, &attrs, &expiry)` |
| Done flag | `major == GSS_S_COMPLETE` | `status == SEC_E_OK` |
| Continue flag | `major == GSS_S_CONTINUE_NEEDED` | `status == SEC_I_CONTINUE_NEEDED` |
| Output blob | `output_token.value` / `output_token.length` | `SecBuffer` with `BufferType = SECBUFFER_TOKEN` |
| Free output blob | `gss_release_buffer` | `FreeContextBuffer` (when `ISC_REQ_ALLOCATE_MEMORY` is requested) |
| Free context | `gss_delete_sec_context` | `DeleteSecurityContext` |
| Free creds | `gss_release_cred` | `FreeCredentialsHandle` |
| Status text | `gss_display_status(major, GSS_C_GSS_CODE, ...)` | `FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, status, ...)` |

**Flags chosen:** `ISC_REQ_MUTUAL_AUTH | ISC_REQ_REPLAY_DETECT |
ISC_REQ_SEQUENCE_DETECT | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY |
ISC_REQ_INTEGRITY` — mirrors the GSSAPI flags in `Krb5Authenticator::DoSecContextStep`.

**Wide-char surface:** Windows SSPI's primary entrypoints are wide-character
(`...W` suffix). We convert UTF-8 SPN → UTF-16 via `MultiByteToWideChar` at
the boundary, exactly once, in the constructor. The rest of the
`WinSspiAuthenticator` operates on `std::wstring`.

## Error taxonomy mapping (spec 042 R8)

| Cause | GSSAPI (POSIX) | SSPI (Windows) |
|---|---|---|
| No credentials available | `KRB5_FCC_NOFILE` / `KRB5_CC_NOTFOUND` | `SEC_E_NO_CREDENTIALS` |
| Expired ticket | `KRB5KRB_AP_ERR_TKT_EXPIRED` | `SEC_E_CONTEXT_EXPIRED` |
| SPN not in KDC | `KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN` | `SEC_E_TARGET_UNKNOWN` |
| Clock skew | `KRB5KRB_AP_ERR_SKEW` | `SEC_E_TIME_SKEW` |
| KDC unreachable | `KRB5_KDC_UNREACH` | `SEC_E_NO_AUTHENTICATING_AUTHORITY` |
| Wrong realm in target | `KRB5_REALM_UNKNOWN` | `SEC_E_WRONG_PRINCIPAL` |
| Generic auth failed | various | `SEC_E_LOGON_DENIED` |

Each row maps to the same hint vocabulary already in
`Krb5Authenticator::HintForMinor`. A new `winsspi_authenticator.cpp` helper
`HintForStatus(SECURITY_STATUS)` returns the same string set so user-facing
error messages are platform-agnostic.

## File layout

```
src/include/tds/auth/winsspi_authenticator.hpp   (new, ~80 lines, no DuckDB headers)
src/tds/auth/winsspi_authenticator.cpp           (new, ~250 lines)
src/tds/auth/auth_strategy_factory.cpp           (modify: 1 branch — replace the stub)
test/sql/integrated_auth/winsspi_basic.test      (new, gated on MSSQL_WINSSPI_TEST=1)
test/sql/integrated_auth/parsing.test            (extend: add winsspi parser cases)
Kerberos.md                                      (modify: replace "Phase 4 not yet shipped")
docs/architecture.md                             (modify: mark WinSspi shipped)
CLAUDE.md                                        (modify: mark Phase 4 done)
CHANGELOG.md                                     (modify: add Phase 4 entry to Unreleased)
specs/042-integrated-authentication/tasks.md     (modify: tick T031-T034)
```

No changes to:
- `CMakeLists.txt` — `secur32` linkage already set up in Phase 2 T006
- `iauthenticator.hpp` — interface is final
- `integrated_auth_strategy.hpp` — works with any `IAuthenticator`
- `BuildLogin7WithSSPI` / `BuildSSPIMessage` — generic across POSIX / Windows
- `tds_token_parser.cpp` — `0xED` handler is platform-neutral

## Test plan

### Build-time

Windows CI workflow `.github/workflows/ci.yml` already has `build-windows-msvc`
and `build-windows-mingw` jobs gated on `workflow_dispatch.run_windows_build`.
The user (or whoever has Windows access) triggers these via
`Actions → CI → Run workflow → Run Windows build jobs` on the
`feat/042-phase4-winsspi` branch. The plan:

1. Push the code.
2. Trigger `run_windows_build` on the branch.
3. Read compile errors from CI logs.
4. Iterate — each cycle is ~10-15 min.
5. Repeat until build green on both MSVC and MinGW.

### Compile-time correctness (what I CAN validate locally)

- The non-`_WIN32` parts (no Windows code paths touched on macOS / Linux)
  should still build cleanly on macOS + Linux. Run the standard `[integration]`
  and `[sql]` tag suites — both should remain at 30/30 and 16/16 pass.
- The parser-level conflict tests (`parsing.test`) must accept new
  `winsspi`-specific cases without regressing.

### Runtime correctness (what falls to the user)

- ATTACH against an AD-joined Windows SQL Server from a domain-joined Windows
  client with `Trusted_Connection=yes`.
- `mssql_kerberos_auth_test('host')` — already exists; on Windows the
  function should also work since the factory dispatch is the same. May want
  to also surface a `mssql_winsspi_auth_test` alias for clarity, OR have
  `mssql_kerberos_auth_test` auto-detect platform.
- Verify negative cases: locked account, expired credentials, wrong SPN —
  each should produce the right `SEC_E_*` mapped error with hint.

### Integration tests

`test/sql/integrated_auth/winsspi_basic.test`:

```sqllogictest
# name: test/sql/integrated_auth/winsspi_basic.test
# description: Spec 042 Phase 4 -- Windows SSPI smoke test.
# group: [winsspi]

require mssql
require-env MSSQL_WINSSPI_TEST

statement ok
ATTACH 'Server=${MSSQL_TEST_HOST};Database=${MSSQL_TEST_DB};Trusted_Connection=yes;Encrypt=yes;TrustServerCertificate=yes'
    AS wsspi (TYPE mssql);

query IT
SELECT TOP 1 schema_name, table_name FROM duckdb_tables() WHERE database_name = 'wsspi' AND schema_name = 'dbo';
----
dbo	<some_table>

statement ok
DETACH wsspi;
```

Tagged `[winsspi]` and gated on `MSSQL_WINSSPI_TEST=1` so non-Windows CI
runners skip cleanly.

### parsing.test additions

Add Windows-specific cases that document the platform restriction:

```sqllogictest
# Test 15: authenticator=krb5 on Windows is rejected (use winsspi instead)
statement error
ATTACH 'Server=...;authenticator=krb5' AS k (TYPE mssql);
----
'authenticator=krb5' is only supported on POSIX

# Test 16: authenticator=winsspi on POSIX is rejected (use krb5 instead)
statement error
ATTACH 'Server=...;authenticator=winsspi' AS k (TYPE mssql);
----
'authenticator=winsspi' is only supported on Windows
```

The conflict checks already exist in `ValidateAuthConflicts` — this just
adds explicit test coverage.

## Risks I cannot validate without Windows access

1. **`SecBuffer` / `SecBufferDesc` setup.** Easy to get the indirection
   wrong (size in elements vs bytes, version field). Mitigated by mirroring
   `go-mssqldb`'s `winsspi.go` closely.
2. **String encoding for SPN.** `InitializeSecurityContextW` takes
   `SEC_WCHAR *`. The conversion path is `std::string → MultiByteToWideChar
   → std::wstring`. Easy to mess up the buffer length parameter.
3. **`ISC_REQ_ALLOCATE_MEMORY` lifetime.** When set, SSPI allocates the
   output token buffer; we must free it via `FreeContextBuffer`. Skipping
   the free is a per-call leak (small) but adds up.
4. **MSVC vs MinGW differences.** MinGW's `<sspi.h>` may have slightly
   different prototypes or missing macros. Two CI jobs catch this.
5. **Thread safety of `secur32.dll`.** Microsoft documents SSPI as
   thread-safe at the function level, but the `CredHandle` and `CtxtHandle`
   are not — must not be shared between threads. Same constraint as GSSAPI;
   the existing pool-factory design (one authenticator per connection)
   already enforces this.
6. **Cross-realm via Negotiate.** Negotiate can drop down to NTLM if the
   KDC is unreachable. We want Kerberos-only; setting `ISC_REQ_DELEGATE`
   does not prevent NTLM fallback. If a deployment NEEDS Kerberos-only,
   they should use Kerberos SSP directly (`L"Kerberos"` instead of
   `L"Negotiate"`) — but that breaks PRELOGIN-FEDAUTHREQUIRED-style
   negotiation. Document as a known limitation.

## Iteration plan

1. **Day 1**: write `winsspi_authenticator.{hpp,cpp}` mirroring
   `krb5_authenticator.cpp`. Push to `feat/042-phase4-winsspi`.
2. **Day 1**: trigger Windows CI via Actions UI. Read compile errors.
3. **Day 1-2**: iterate compile fixes until both MSVC and MinGW jobs green.
4. **Day 2**: wire factory; replace the "Phase 4 not yet implemented" stub.
5. **Day 2**: write `winsspi_basic.test` + parsing.test additions.
6. **Day 2**: update Kerberos.md / CLAUDE.md / docs/architecture.md /
   CHANGELOG.md / tasks.md.
7. **Day 2**: open PR.
8. **Day 2**: user runs `/ultrareview` on the PR.
9. **Day 2-3**: address findings, re-iterate Windows CI.
10. **Day 3**: user validates against a real domain-joined Windows host.
11. **Day 3**: merge.

## Upstream PR plan (after Phase 4 merges to oluies/mssql-extension main)

1. Add `hugr-lab/mssql-extension` as `upstream` remote (read-only).
2. Create branch `integrated-security` on `oluies/mssql-extension`, fast-forwarded
   to the post-Phase-4 main.
3. Push to oluies as a new branch.
4. Open PR from `oluies:integrated-security` → `hugr-lab/mssql-extension:main`
   (or whatever the upstream target branch is — confirm with hugr-lab).
5. PR body: link to spec 042, summarize phases 1-4, list the four PRs (#5, #6,
   plus this Phase 4 PR) that comprise the work. Reference the `test/kerberos/`
   stack for reviewer verification.
6. Tag a release on oluies (e.g. `v0.2.0` since this is a feature-level addition)
   so users can install from the fork while the upstream PR is in review.

## Out-of-scope items (would be Phase 5+)

- Channel binding / EPA (RFC 5929 tls-server-end-point) — needed for
  hardened SQL Server deployments. Requires extracting the TLS peer cert
  signature and binding it into the SPNEGO blob.
- NTLM-only fallback path (servers without a registered SPN). The Negotiate
  package handles this transparently; making it explicit would require a
  separate `authenticator=ntlm` value and a new authenticator implementation.
- Cross-realm trust corner cases. The Negotiate package handles transitive
  trust transparently when KDCs are reachable; documenting failure modes
  for misconfigured trusts is a future doc task.
- Constrained delegation (S4U2Self / S4U2Proxy). DuckDB doesn't impersonate
  end users today, so there's no use case yet.

## Verification when complete

- [ ] Build green on macOS arm64, Linux x86_64 / arm64, Windows MSVC, Windows MinGW.
- [ ] `[integration]`, `[sql]`, and `[mssql]` tag groups still pass unchanged.
- [ ] `test/sql/integrated_auth/parsing.test` gains 2 new conflict cases (krb5-on-Windows, winsspi-on-POSIX), passes.
- [ ] `test/sql/integrated_auth/winsspi_basic.test` runs when `MSSQL_WINSSPI_TEST=1` is set on a domain-joined Windows host.
- [ ] User validates manual ATTACH from a real domain-joined Windows client.
- [ ] `Kerberos.md` Windows section no longer says "Phase 4 not yet shipped".
- [ ] `CHANGELOG.md` Unreleased section has a Phase 4 entry.
- [ ] `specs/042-integrated-authentication/tasks.md` has T031-T034 checked.

## Open questions to confirm before code lands

1. **`mssql_kerberos_auth_test` on Windows** — should it work as-is (the
   factory dispatches `WINSSPI` and the test function exercises the same
   `IAuthenticator::InitialBytes()` path), or should we add a separate
   `mssql_winsspi_auth_test` for clarity? My instinct: keep the existing
   function name; it's about "Integrated Auth", not specifically Kerberos.
2. **Negotiate vs Kerberos package** — Negotiate allows NTLM fallback,
   Kerberos doesn't. Negotiate is what go-mssqldb / mssql-jdbc / pyodbc all
   use; Kerberos-only is a hardening option. Stick with Negotiate; doc the
   tradeoff.
3. **MinGW or MSVC-only?** Existing CI builds both. We support both — but
   MinGW's headers may need workarounds. If MinGW becomes painful, scope
   it to MSVC-only with documentation.
