## ADDED Requirements

### Requirement: Password hashing runs behind a bounded admission gate
Every Argon2id operation SHALL take a permit from a KDF admission gate before it runs. This includes hashing and verifying user passwords, re-hashing a stale or legacy credential, and verifying an Argon2id client secret. A request that waits for a permit SHALL hold no request-handling thread while it waits.

The server SHALL have two gates:

- The **shared** gate serves every Argon2id operation except admin console login. It has `max_in_flight` permits.
- The **admin** gate serves `/ui/admin/login` only. It has `admin_max_in_flight` permits. Admin console login SHALL NOT take a permit from the shared gate.

A request that gets no permit within its queue wait SHALL be shed: it SHALL get `503 Service Unavailable` with `Retry-After` set to `retry_after_seconds`, and its Argon2id operation SHALL NOT run. Each gate SHALL count its sheds.

| Key (`security.password.kdf.*`) | Default | Meaning |
|-----|---------|---------|
| `max_in_flight` | host core count | Permits in the shared gate |
| `admin_max_in_flight` | `2` | Permits in the admin gate |
| `max_queue_wait_ms` | `250` | Queue wait of an untrusted request in the shared gate |
| `trusted_max_queue_wait_ms` | `2500` | Queue wait of a trusted sign-in attempt in the shared gate |
| `admin_max_queue_wait_ms` | `2500` | Queue wait in the admin gate |
| `retry_after_seconds` | `1` | `Retry-After` value on a shed response |
| `pressure_window_secs` | `10` | How long the shared gate stays under pressure after an untrusted shed |
| `nice` | `5` | CPU priority offset of Argon2id work; `0` disables it |

An explicit `0` for `max_in_flight`, `admin_max_in_flight`, `max_queue_wait_ms`, `trusted_max_queue_wait_ms` or `admin_max_queue_wait_ms` SHALL be refused at startup. A `nice` value outside `0` to `19` SHALL be refused at startup.

#### Scenario: Concurrent hashing is bounded
- **WHEN** more password sign-ins arrive at once than the shared gate has permits
- **THEN** no more than `max_in_flight` Argon2id operations run at the same time in the shared gate

#### Scenario: An untrusted request waits too long
- **WHEN** an untrusted request waits `max_queue_wait_ms` for a shared permit and gets none
- **THEN** it receives `503` with `Retry-After: 1`
- **AND** no Argon2id work is done for it

#### Scenario: A tenant flood does not block the operator
- **WHEN** every shared permit is held by a flood against a tenant realm's login form
- **THEN** an admin console login still gets a permit from the admin gate

#### Scenario: A zero bound is refused
- **WHEN** `hearth.yaml` sets `security.password.kdf.max_in_flight: 0`
- **THEN** the server refuses to start and names the key

### Requirement: The shared gate admits trusted sign-in attempts first
The shared gate SHALL classify each waiter as trusted or untrusted. A login-form attempt that A-53 trusts SHALL be a trusted waiter. Every other request SHALL be an untrusted waiter. When a permit becomes free and a trusted waiter is queued, the gate SHALL give the permit to the trusted waiter that has waited longest. The gate SHALL give a permit to an untrusted waiter only when no trusted waiter is queued.

#### Scenario: A real user gets ahead of a flood
- **WHEN** every shared permit is held and many untrusted attempts are queued
- **AND** a trusted attempt then joins the queue
- **THEN** the trusted attempt gets the next permit that becomes free

#### Scenario: A trusted attempt waits longer before it is shed
- **WHEN** a trusted attempt is queued while untrusted attempts are being shed after `max_queue_wait_ms`
- **THEN** the trusted attempt is not shed before `trusted_max_queue_wait_ms`

### Requirement: A permit covers the Argon2id work only
A request SHALL hold its KDF permit only while its Argon2id work runs. For a password sign-in, the permit SHALL cover the credential verify and, when the credential needs one, its re-hash. The request SHALL release the permit before it runs the second-factor check, the required-action check, session issuance or audit writes. The `hearth_kdf_compute_seconds` histogram SHALL measure only the time a permit is held.

#### Scenario: Session issuance runs after the permit is released
- **WHEN** a password sign-in verifies and then creates a session
- **THEN** the shared gate counts the permit as free before the session is written

#### Scenario: The compute metric measures the hash
- **WHEN** a password sign-in completes
- **THEN** the `hearth_kdf_compute_seconds` observation for it does not include the time spent in session issuance

### Requirement: The shared gate reports pressure
The shared gate SHALL be under pressure from the moment it sheds an untrusted waiter until `pressure_window_secs` pass with no untrusted shed. The gauge `hearth_kdf_pressure` SHALL be `1` while the gate is under pressure and `0` otherwise. Reading the pressure state SHALL NOT take a lock that a gate operation holds.

#### Scenario: A shed starts the pressure window
- **WHEN** the shared gate sheds an untrusted waiter
- **THEN** `hearth_kdf_pressure` is `1`

#### Scenario: Pressure ends
- **WHEN** `pressure_window_secs` pass with no untrusted shed
- **THEN** `hearth_kdf_pressure` is `0`

### Requirement: Passkey sign-in takes no hashing permit
A passkey sign-in SHALL NOT take a permit from any KDF admission gate. A shed by the shared gate SHALL NOT refuse a passkey sign-in.

#### Scenario: Passkeys work during a password flood
- **WHEN** every shared permit is held and the gate sheds untrusted password attempts
- **THEN** a passkey sign-in with a valid assertion succeeds

### Requirement: Password hashing yields CPU to request handling
On Linux, the threads that run Argon2id work SHALL run at a nice value `nice` higher than the threads that handle requests. When `nice` is `0`, they SHALL run at the same priority. On other platforms, the setting SHALL have no effect, and the server SHALL log once at startup that it is ignored.

#### Scenario: Hashing threads run at a lower priority
- **WHEN** the server runs on Linux with `security.password.kdf.nice: 5`
- **THEN** each thread that runs Argon2id work has a nice value 5 higher than the request-handling threads

#### Scenario: The priority change is turned off
- **WHEN** the server runs with `security.password.kdf.nice: 0`
- **THEN** the threads that run Argon2id work have the same nice value as the request-handling threads
