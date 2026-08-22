"""Connected mode: collectors that produce an export, out of process.

READ THIS BEFORE ADDING ANYTHING HERE.

WHAT THIS PACKAGE IS
--------------------
A collector reads from a system the operator authorises and WRITES THE SAME FILES
a customer would export by hand. That is the whole contract. The scanner cannot
tell which produced them, because there is one ingestion path and this is not a
second one:

    online   SAP instance ──HTTPS──> collect/ ──writes──> extract files ─┐
                                                                         ├─> DataLoader ──> modules/
    offline  the customer's own export ─────────────────────────────────┘

Both modes converge before the first check runs. That is what makes connected
mode affordable rather than a second product: it inherits every test the offline
path already has, and `modules/` never learns that a network exists.

FOUR RULES, AND THEY ARE STRUCTURAL RATHER THAN ASPIRATIONAL
------------------------------------------------------------
1. NOTHING IN `server/` OR `modules/` MAY IMPORT THIS PACKAGE.
   `tests/test_collect.py` asserts it. A connector that gets imported into the
   product is a live API client inside the product, which is the thing decision
   D2 declined — the objection was never to reaching SAP, it was to network code
   living behind the stdlib-only boundary where its failures are invisible.

2. DELETING THIS DIRECTORY MUST LEAVE EVERY TEST PASSING AND THE IMAGE BUILDING.
   Also asserted. It is the mechanical form of "optional".

3. STDLIB ONLY. Decision D4 permits `collect/` its own requirements. It does not
   spend that allowance, because urllib, ssl and xml.etree cover SOAP, OData,
   SCIM and REST — and a connector tier with NO dependencies is a stronger
   position than one with different ones. The `purity` CI job covers this
   directory for that reason.

4. READ-ONLY, ENFORCED RATHER THAN INTENDED. Every connector declares the exact
   operations it may perform, and the transport refuses anything else. This is
   not fastidiousness: the SAPControl interface this package speaks to also
   offers Start, Stop, Restart and OS-command execution on the same endpoint and
   the same port. A typo must not be able to stop a production instance.

WHAT CONNECTED MODE IS NOT
--------------------------
It is not a replacement for an export, and it must never present as one. Some
surfaces on ECC are reachable only over RFC, which this product declines
(decision D3) — so a connected collection is PARTIAL by construction. Every run
writes a manifest saying what it obtained and what it did not, and the scanner
reads that manifest as degraded coverage. A connected run that silently omitted
half the estate and reported clean would be the same "we could not look, so we
said nothing" failure the release gate exists to refuse.
"""

__all__ = ["__version__"]

__version__ = "1.0.0"
