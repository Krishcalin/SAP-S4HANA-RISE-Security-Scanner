# Synthetic landscape — P01 · T01 · D01

A fictitious three-system SAP landscape for demonstration and testing. Generated
by [`tools/build_landscape_fixture.py`](../tools/build_landscape_fixture.py);
regenerate with `python -m tools.build_landscape_fixture`.

```
   D01                    T01                    P01
   development  ──TR──>   test  ──TR──>          production
   client 300             client 200             client 100
   SAP_BASIS 755          SAP_BASIS 755          SAP_BASIS 755

   D01 ─────────── RFC P01_TRANSPORT, credential STORED ──────────> P01
                   (runs as RFC_D01_IN, which holds SAP_ALL in P01)
```

## Why it is three systems and not one more single system

`sample_data/` is one S/4HANA system and `sample_data_ecc/` is one ECC system.
Neither can exercise the thing this product is actually for: **a trust edge from
a lower tier into production**. That is the single most load-bearing fact the
attack-path engine derives, and until this fixture existed it could only be
tested with hand-built rows rather than demonstrated end to end.

## The story, and that the scanner finds it unaided

Every finding below came out of a normal scan of the generated directories —
nothing was planted in the expected output.

**1 · Getting into D01 is trivial.**

| | |
|---|---|
| `STDUSR-002` CRITICAL | `SAP*` (client 300) — default password still valid |
| `STDUSR-003` HIGH | `SAP*` (client 300) — unlocked, dialog-capable |
| `STDUSR-001` CRITICAL | `login/no_automatic_user_sapstar = 0` |

**2 · D01 holds a credential that opens production.**

| | |
|---|---|
| `NET-001` HIGH | `P01_TRANSPORT` → user `RFC_D01_IN` (auth type: **STORED**) |
| `NET-003` HIGH | `P01_TRANSPORT` (type 3, SNC **disabled**) |

`RFC_D01_IN` holds `SAP_ALL` in P01. A stored credential means whoever opens the
destination inherits those rights **without holding an account in P01 at all**.

**3 · Production knows it is exposed, and says so from its own export.**

| | |
|---|---|
| `TRUST-001` HIGH | Trusted system **D01** — *likely NON-PRODUCTION tier* |
| `TRUST-003` HIGH | Trusted system D01 — trust method not migrated |

The scanner worked out the tier relationship itself, from the landscape data.

**4 · And T01 makes it worse, independently.**

| | |
|---|---|
| `DPP-MASK-002` CRITICAL | T01 (env QUALITY) — **production copy without masking** |

Real financial and personal data, in a system with a weaker password policy, a
wider user population including an external tester, and `SAP_ALL` held by a test
user.

**5 · D01's Security Audit Log is off** (`rsau/enable = 0`), and D01 logs only two
of the twelve sensitive tables P01 logs — so a change made in D01 and transported
upward is materially harder to attribute afterwards.

## The hardening gradient

| | findings | CRITICAL | HIGH | MEDIUM | LOW |
|---|---:|---:|---:|---:|---:|
| **P01** production | 79 | 3 | 27 | 39 | 9 |
| **T01** test | 89 | 5 | 30 | 43 | 10 |
| **D01** development | 99 | 8 | 38 | 42 | 10 |

Production is hardened but imperfect, which is what a real estate looks like — a
fixture where production is spotless tests nothing.

## Running it

```bash
python sap_scanner.py --data-dir sample_data_landscape/P01 --output p01.html
python sap_scanner.py --data-dir sample_data_landscape/T01 --output t01.html
python sap_scanner.py --data-dir sample_data_landscape/D01 --output d01.html
```

For the cross-system view — attack paths, the mitigation journey, per-system
scoping — load all three into the server, each attached to its own system in one
landscape:

```bash
python -m server.cli add-landscape "Acme"      --mode on_prem
python -m server.cli add-system    "Acme" P01 100 --tier prod    --criticality critical
python -m server.cli add-system    "Acme" T01 200 --tier qa
python -m server.cli add-system    "Acme" D01 300 --tier dev
python -m server.cli scan "Acme" sample_data_landscape/P01 --sid P01 --client 100
```

## What is synthetic and what is not

**Synthetic:** host names, user names, dates, client numbers, RFC destination
names, and every parameter *value*.

**Not synthetic — and deliberately so:** every SAP *identifier*. Parameter names,
profile names (`SAP_ALL`, `SAP_NEW`, `S_A.SYSTEM`), standard users (`SAP*`,
`DDIC`, `EARLYWATCH`, `SAPCPIC`, `TMSADM`), RFC connection types (`3`, `T`, `W`),
logged table names (`USR02`, `RFCDES`, `T000`, `BKPF`, `PA0001`) and component
names are all real, taken from the shipped rule tables and the existing fixtures.

That line matters: inventing a plausible-looking SAP identifier would put a false
fact into a document that looks authoritative, which this repository forbids. Two
checks enforce it — every parameter name in the fixture is one some module
actually reads, and every filename is one `DataLoader` recognises.

Each system also carries `export_completeness.json` declaring `security_params`
complete, which is honest here because the generator writes the parameter list in
full. Absent that declaration the scanner would disclose the unlisted parameters
as coverage gaps rather than judging them — see
[docs/EXPORT_GUIDE.md](../docs/EXPORT_GUIDE.md).

**Do not** use this data to make claims about a real SAP system, and do not copy
its values into a real baseline. It exists to exercise the scanner.
