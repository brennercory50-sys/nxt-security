# Findings and triage

Modules raise **findings**; the finding engine deduplicates them across
assessments (one record per fingerprint) and lets you triage each one through
a validated state machine with an auditable history.

## Statuses and transitions

```
OPEN ──► CONFIRMED ──► MITIGATED ──► CLOSED
 │  │        │  │          │
 │  │        │  └► ACCEPTED ┘
 │  └────────┴► FALSE_POSITIVE
 └► ACCEPTED / CLOSED
FALSE_POSITIVE ──► OPEN     (reopen)
CLOSED ──────────► OPEN     (reopen)
```

`OPEN` and `CONFIRMED` count as *open* (still demanding attention). Every
change records who, when, the transition, and an optional note; notes are kept
and shown in `findings show` and reports. Invalid transitions are refused with
the list of allowed next states.

## Commands

```sh
nxtsec findings list [--status S] [--min-severity MEDIUM] [--module M] [--open]
nxtsec findings show <id|prefix>
nxtsec findings set-status <id|prefix> CONFIRMED --note "reproduced"
nxtsec findings note <id|prefix> "owner notified"
nxtsec findings stats
```

Findings are listed most-severe-first. Any id can be given by a unique prefix.
