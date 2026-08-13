# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
RFC collector — the surfaces HTTPS cannot reach, bound to the SDK by ctypes.

WHY THIS EXISTS, AND WHY IT LOOKS LIKE THIS
-------------------------------------------
Decision D3 declined RFC and delivered connected mode over HTTPS instead. That
decision stands: `collect/sapcontrol.py` and `collect/icf.py` reach what they can
without an SDK, and most customers should use them.

But sixteen logical sources are RFC-only — `users`, `profiles`, `roles`,
`role_profiles`, `auth_objects`, `rfc_destinations`, `client_settings`,
`change_documents`, `background_jobs`, `gateway_acl`, `audit_log_config` and more.
That is the whole IAM and segregation-of-duties family plus the trust data behind
cross-system attack paths. `collect/extract.py` names them in ICF_CANNOT_REACH,
and until now they were export-only.

THERE IS NO BINDING LEFT TO DEPEND ON, SO WE DEPEND ON NONE
-----------------------------------------------------------
PyRFC was archived on 28 May 2026 and its PyPI releases were yanked — `pip install
pyrfc` now fails without an exact version pin. SAP discontinued it for want of a
maintainer with access to the SDK source, and discontinued the Node.js and other
bindings at the same time: SAP has exited RFC language bindings, not just Python
ones. There is no official replacement.

Building a security product's most sensitive collector on an archived, yanked
package that will never receive another patch is not a trade worth making. So this
module binds the SDK directly through `ctypes`, which is standard library. The
product's dependency count does not move, `collect/` stays dependency-free, and
nothing here can rot upstream because there is no upstream.

WHAT THE CUSTOMER MUST STILL SUPPLY, AND WHY THE IMAGE IS UNCHANGED
-------------------------------------------------------------------
The SAP NetWeaver RFC SDK itself. It is S-user gated and cannot be redistributed,
which is the fact D3 rests on and it has not changed. So this collector is
OPT-IN and OUT-OF-PROCESS, exactly like the other two: the customer installs the
SDK on a machine that can reach their SAP system, runs `python -m collect rfc`,
and gets the same CSV files the offline path already reads. The container image
does not carry the SDK, does not import this module, and is not affected by its
presence. The one-container property survives intact.

THE ENCODING CONTRACT, WHICH IS WHERE THIS GOES WRONG SILENTLY
---------------------------------------------------------------
SAP_UC is UTF-16LE on every platform. `wchar_t` is NOT: it is UTF-16 on Windows
and a 4-byte UCS-4 on Linux. Every community example of this technique is
Windows-only and uses `ctypes.c_wchar_p`, which on Linux hands the SDK buffers
twice the width it expects — SAP's own guidance warns this produces segmentation
faults "as the buffers you feed into the RFC APIs is only half as long as the RFC
APIs expect them to be".

This product's container is Linux. So every string crossing this boundary is
encoded EXPLICITLY to UTF-16LE and `c_wchar_p` appears nowhere in this file. A
test asserts that, because the natural way to write this code is the broken way.
"""
from __future__ import annotations

import ctypes
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: Function modules this collector may invoke. Everything else is refused before
#: any handle is opened.
#:
#: THE ALLOWLIST MATTERS MORE HERE THAN ANYWHERE ELSE IN THE PRODUCT. sapstartsrv
#: offers a few dozen operations and `collect/soap.py` guards them; RFC exposes
#: EVERY remote-enabled function module in the system, which on a typical estate
#: is tens of thousands — including ones that change user master records, submit
#: jobs, and execute ABAP. A collector that decided at the call site what was safe
#: would be one refactor away from being a remote administration tool.
#:
#: Only these three, and each is read-only by SAP's own definition:
#:   RFC_READ_TABLE   the standard generic table reader
#:   RFC_SYSTEM_INFO  returns the system's own identity and release
#:   RFCPING          connectivity only; takes and returns nothing
READ_ONLY_FUNCTIONS = frozenset({
    "RFC_READ_TABLE",
    "RFC_SYSTEM_INFO",
    "RFCPING",
})

#: Where the SDK lives. The customer sets this; there is no default because a
#: guessed path that happens to exist is worse than a clear failure.
SDK_HOME_ENV = "SAPNWRFC_HOME"

_LIB_NAMES = {
    "win32": "sapnwrfc.dll",
    "darwin": "libsapnwrfc.dylib",
}
_DEFAULT_LIB = "libsapnwrfc.so"


class RfcUnavailable(RuntimeError):
    """The SDK is not installed, or not where SAPNWRFC_HOME says it is."""


class RefusedFunction(RuntimeError):
    """A function module outside the read-only allowlist was requested."""


class RfcCallFailed(RuntimeError):
    """The SDK returned a non-zero RFC_RC."""


# ── SAP_UC ───────────────────────────────────────────────────────────────────

def to_sap_uc(text: str) -> bytes:
    """Encode to SAP_UC: UTF-16LE, NUL-terminated.

    NOT c_wchar_p, and not ctypes.create_unicode_buffer. Both use the platform
    `wchar_t`, which is 4 bytes on Linux where SAP_UC is 2 — the SDK would read
    half the characters it was given and walk off the end of the rest.
    """
    return text.encode("utf-16-le") + b"\x00\x00"


def from_sap_uc(raw: bytes) -> str:
    """Decode a SAP_UC buffer, stopping at the first NUL character."""
    text = raw.decode("utf-16-le", errors="replace")
    end = text.find("\x00")
    return (text[:end] if end >= 0 else text).rstrip()


def uc_buffer(chars: int) -> ctypes.Array:
    """A writable SAP_UC buffer of `chars` characters (2 bytes each)."""
    return ctypes.create_string_buffer(chars * 2)


# ── structs ──────────────────────────────────────────────────────────────────
#
#  Layout follows the published sapnwrfc.h. The character arrays are declared
#  with the header's +1 for the terminator, and the whole struct is then padded
#  generously by `_ERROR_INFO_SLACK`.
#
#  THE PADDING IS DELIBERATE AND IS A SAFETY MARGIN, NOT TIDINESS. This code
#  cannot verify the header against the customer's SDK version — the SDK is not
#  redistributable, so it is not here to check. Passing a struct SMALLER than the
#  library expects is a buffer overflow in a security tool; passing a larger one
#  is harmless, because the library writes at its own offsets and stops. If a
#  future SDK grows the struct, the extra room absorbs it.

_RC = ctypes.c_int
_GROUP = ctypes.c_int
_ERROR_INFO_SLACK = 512          # bytes of headroom beyond the published layout


class RfcErrorInfo(ctypes.Structure):
    _fields_ = [
        ("code", _RC),
        ("group", _GROUP),
        ("key", ctypes.c_char * ((128 + 1) * 2)),
        ("message", ctypes.c_char * ((512 + 1) * 2)),
        ("abapMsgClass", ctypes.c_char * ((20 + 1) * 2)),
        ("abapMsgType", ctypes.c_char * ((1 + 1) * 2)),
        ("abapMsgNumber", ctypes.c_char * ((3 + 1) * 2)),
        ("abapMsgV1", ctypes.c_char * ((50 + 1) * 2)),
        ("abapMsgV2", ctypes.c_char * ((50 + 1) * 2)),
        ("abapMsgV3", ctypes.c_char * ((50 + 1) * 2)),
        ("abapMsgV4", ctypes.c_char * ((50 + 1) * 2)),
        ("_slack", ctypes.c_char * _ERROR_INFO_SLACK),
    ]

    def describe(self) -> str:
        key = from_sap_uc(self.key)
        message = from_sap_uc(self.message)
        return f"{key}: {message}".strip(": ") or f"RFC_RC={self.code}"


class RfcConnectionParameter(ctypes.Structure):
    """One name/value pair. Both are SAP_UC pointers, so both are UTF-16LE."""
    _fields_ = [("name", ctypes.c_void_p), ("value", ctypes.c_void_p)]


# ── the library ──────────────────────────────────────────────────────────────

def sdk_library_path(home: Optional[str] = None) -> str:
    """Where the SDK shared library should be, given SAPNWRFC_HOME."""
    root = home or os.environ.get(SDK_HOME_ENV)
    if not root:
        raise RfcUnavailable(
            f"{SDK_HOME_ENV} is not set. The SAP NetWeaver RFC SDK is downloaded "
            f"from SAP under your own S-user licence and cannot be redistributed, "
            f"so this collector cannot supply it. Install it, then set "
            f"{SDK_HOME_ENV} to the directory containing lib/.")
    return os.path.join(root, "lib", _LIB_NAMES.get(sys.platform, _DEFAULT_LIB))


def load_sdk(home: Optional[str] = None) -> ctypes.CDLL:
    """Load the SDK, or explain precisely what is missing.

    Errors here are the ones a customer will actually hit, so they name the file
    that was looked for rather than reporting that something went wrong.
    """
    path = sdk_library_path(home)
    if not os.path.isfile(path):
        raise RfcUnavailable(
            f"no SDK library at {path}. Check that {SDK_HOME_ENV} points at the "
            f"unpacked nwrfcsdk directory (the one containing lib/ and include/).")
    try:
        lib = ctypes.CDLL(path)
    except OSError as exc:
        raise RfcUnavailable(
            f"{path} exists but could not be loaded: {exc}. On Linux the SDK's "
            f"lib/ directory usually has to be on LD_LIBRARY_PATH as well, "
            f"because libsapnwrfc.so loads its own siblings at runtime.") from exc
    _declare(lib)
    return lib


def _declare(lib: ctypes.CDLL) -> None:
    """Argument and return types for every SDK entry point used here.

    Declared explicitly rather than left to ctypes' defaults: an undeclared
    pointer return is truncated to 32 bits on 64-bit builds, which turns a valid
    connection handle into a wild pointer.
    """
    P = ctypes.c_void_p
    E = ctypes.POINTER(RfcErrorInfo)

    lib.RfcOpenConnection.argtypes = [ctypes.POINTER(RfcConnectionParameter),
                                      ctypes.c_uint, E]
    lib.RfcOpenConnection.restype = P

    lib.RfcCloseConnection.argtypes = [P, E]
    lib.RfcCloseConnection.restype = _RC

    lib.RfcGetFunctionDesc.argtypes = [P, ctypes.c_char_p, E]
    lib.RfcGetFunctionDesc.restype = P

    lib.RfcCreateFunction.argtypes = [P, E]
    lib.RfcCreateFunction.restype = P

    lib.RfcDestroyFunction.argtypes = [P, E]
    lib.RfcDestroyFunction.restype = _RC

    lib.RfcInvoke.argtypes = [P, P, E]
    lib.RfcInvoke.restype = _RC

    lib.RfcSetChars.argtypes = [P, ctypes.c_char_p, ctypes.c_char_p,
                                ctypes.c_uint, E]
    lib.RfcSetChars.restype = _RC

    lib.RfcGetTable.argtypes = [P, ctypes.c_char_p, ctypes.POINTER(P), E]
    lib.RfcGetTable.restype = _RC

    lib.RfcGetRowCount.argtypes = [P, ctypes.POINTER(ctypes.c_uint), E]
    lib.RfcGetRowCount.restype = _RC

    lib.RfcMoveToFirstRow.argtypes = [P, E]
    lib.RfcMoveToFirstRow.restype = _RC

    lib.RfcMoveToNextRow.argtypes = [P, E]
    lib.RfcMoveToNextRow.restype = _RC

    lib.RfcGetCurrentRow.argtypes = [P, E]
    lib.RfcGetCurrentRow.restype = P

    lib.RfcGetChars.argtypes = [P, ctypes.c_char_p, ctypes.c_char_p,
                                ctypes.c_uint, E]
    lib.RfcGetChars.restype = _RC

    lib.RfcAppendNewRow.argtypes = [P, E]
    lib.RfcAppendNewRow.restype = P


# ── connection ───────────────────────────────────────────────────────────────

class Connection:
    """One RFC connection that cannot invoke anything outside the allowlist."""

    def __init__(self, params: Dict[str, str], *,
                 home: Optional[str] = None,
                 allowed: frozenset = READ_ONLY_FUNCTIONS,
                 lib: Optional[ctypes.CDLL] = None) -> None:
        #: Passed in rather than defaulted inside the transport, so the permitted
        #: set is visible where the connection is made. Same rule as soap.py.
        self.allowed = allowed
        self._lib = lib or load_sdk(home)
        self._handle: Optional[int] = None
        self._params = dict(params)

    # -- lifecycle ----------------------------------------------------------
    def open(self) -> "Connection":
        err = RfcErrorInfo()
        n = len(self._params)
        arr = (RfcConnectionParameter * n)()
        # The encoded buffers must outlive the call: ctypes does not keep a
        # reference to a temporary passed as c_void_p, and a freed buffer here
        # would be a use-after-free inside the SDK.
        self._keepalive: List[bytes] = []
        for i, (k, v) in enumerate(self._params.items()):
            kb, vb = to_sap_uc(k), to_sap_uc(str(v))
            self._keepalive += [kb, vb]
            arr[i].name = ctypes.cast(ctypes.c_char_p(kb), ctypes.c_void_p)
            arr[i].value = ctypes.cast(ctypes.c_char_p(vb), ctypes.c_void_p)
        handle = self._lib.RfcOpenConnection(arr, n, ctypes.byref(err))
        if not handle:
            raise RfcCallFailed(f"RfcOpenConnection failed - {err.describe()}")
        self._handle = handle
        return self

    def close(self) -> None:
        if self._handle:
            err = RfcErrorInfo()
            self._lib.RfcCloseConnection(self._handle, ctypes.byref(err))
            self._handle = None

    def __enter__(self) -> "Connection":
        return self.open()

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # -- invocation ---------------------------------------------------------
    def _function(self, name: str):
        """Resolve and instantiate a function module, allowlist first.

        THE ORDER IS THE SAFETY PROPERTY, as in soap.py: the allowlist is
        consulted before any handle is created and before anything reaches the
        network, so a function module this collector may not call cannot be sent
        to a system that would happily run it.
        """
        if name not in self.allowed:
            raise RefusedFunction(
                f"{name!r} is not in this collector's read-only allowlist "
                f"({', '.join(sorted(self.allowed))}). RFC exposes every "
                f"remote-enabled function module in the system — including ones "
                f"that change user master records and execute ABAP — so the "
                f"allowlist is enforced here rather than trusted to callers.")
        if not self._handle:
            raise RfcCallFailed("connection is not open")
        err = RfcErrorInfo()
        desc = self._lib.RfcGetFunctionDesc(self._handle, to_sap_uc(name),
                                            ctypes.byref(err))
        if not desc:
            raise RfcCallFailed(f"RfcGetFunctionDesc({name}) - {err.describe()}")
        func = self._lib.RfcCreateFunction(desc, ctypes.byref(err))
        if not func:
            raise RfcCallFailed(f"RfcCreateFunction({name}) - {err.describe()}")
        return func

    def _invoke(self, func) -> None:
        err = RfcErrorInfo()
        rc = self._lib.RfcInvoke(self._handle, func, ctypes.byref(err))
        if rc != 0:
            raise RfcCallFailed(f"RfcInvoke - {err.describe()}")

    def ping(self) -> bool:
        """RFCPING: reachable and credentials accepted, and nothing else."""
        func = self._function("RFCPING")
        try:
            self._invoke(func)
            return True
        finally:
            self._lib.RfcDestroyFunction(func, ctypes.byref(RfcErrorInfo()))

    def read_table(self, table: str, fields: Sequence[str],
                   where: str = "", row_limit: int = 0) -> List[Dict[str, str]]:
        """Read a table through RFC_READ_TABLE.

        RFC_READ_TABLE HAS A HARD 512-BYTE ROW LIMIT, imposed by its own DATA
        structure, and it is the reason `fields` is required rather than optional.
        Asking for every column of USR02 exceeds it and the call fails with
        DATA_BUFFER_EXCEEDED — which reads like a connectivity problem and is not
        one. Naming the columns keeps the row inside the limit and keeps the
        extract to what the auditors actually read.
        """
        func = self._function("RFC_READ_TABLE")
        err = RfcErrorInfo()
        try:
            self._lib.RfcSetChars(func, to_sap_uc("QUERY_TABLE"),
                                  to_sap_uc(table), len(table),
                                  ctypes.byref(err))
            self._lib.RfcSetChars(func, to_sap_uc("DELIMITER"),
                                  to_sap_uc("|"), 1, ctypes.byref(err))
            if row_limit:
                limit = str(row_limit)
                self._lib.RfcSetChars(func, to_sap_uc("ROWCOUNT"),
                                      to_sap_uc(limit), len(limit),
                                      ctypes.byref(err))
            self._fill_table(func, "FIELDS", "FIELDNAME", fields)
            if where:
                self._fill_table(func, "OPTIONS", "TEXT", _split_where(where))
            self._invoke(func)
            return self._read_rows(func, fields)
        finally:
            self._lib.RfcDestroyFunction(func, ctypes.byref(RfcErrorInfo()))

    # -- table helpers ------------------------------------------------------
    def _table_handle(self, func, name: str):
        err = RfcErrorInfo()
        handle = ctypes.c_void_p()
        rc = self._lib.RfcGetTable(func, to_sap_uc(name), ctypes.byref(handle),
                                   ctypes.byref(err))
        if rc != 0:
            raise RfcCallFailed(f"RfcGetTable({name}) - {err.describe()}")
        return handle

    def _fill_table(self, func, table_name: str, column: str,
                    values: Sequence[str]) -> None:
        handle = self._table_handle(func, table_name)
        err = RfcErrorInfo()
        for value in values:
            row = self._lib.RfcAppendNewRow(handle, ctypes.byref(err))
            if not row:
                raise RfcCallFailed(
                    f"RfcAppendNewRow({table_name}) - {err.describe()}")
            self._lib.RfcSetChars(row, to_sap_uc(column), to_sap_uc(value),
                                  len(value), ctypes.byref(err))

    def _read_rows(self, func, fields: Sequence[str]) -> List[Dict[str, str]]:
        """Split DATA on the delimiter and zip it back to the field names.

        RFC_READ_TABLE returns one delimited string per row rather than typed
        columns, so the caller's field ORDER is the only thing that maps a value
        to a name. Passing a different order than was requested silently
        mislabels every column, which is why `fields` is threaded through from
        the request rather than re-derived here.
        """
        handle = self._table_handle(func, "DATA")
        err = RfcErrorInfo()
        count = ctypes.c_uint(0)
        self._lib.RfcGetRowCount(handle, ctypes.byref(count), ctypes.byref(err))
        rows: List[Dict[str, str]] = []
        if not count.value:
            return rows
        self._lib.RfcMoveToFirstRow(handle, ctypes.byref(err))
        buf = uc_buffer(512)
        for index in range(count.value):
            if index:
                self._lib.RfcMoveToNextRow(handle, ctypes.byref(err))
            row = self._lib.RfcGetCurrentRow(handle, ctypes.byref(err))
            if not row:
                break
            self._lib.RfcGetChars(row, to_sap_uc("WA"), buf, 512,
                                  ctypes.byref(err))
            parts = from_sap_uc(buf.raw).split("|")
            rows.append({name: (parts[i].strip() if i < len(parts) else "")
                         for i, name in enumerate(fields)})
        return rows


def _split_where(where: str, width: int = 72) -> List[str]:
    """Break a WHERE clause into RFC_READ_TABLE's 72-character OPTIONS rows.

    Split on whitespace, never mid-token: OPTIONS lines are concatenated by the
    function module, and a break inside a literal or an operator produces a
    clause that is valid ABAP and means something else.
    """
    out: List[str] = []
    line = ""
    for token in where.split():
        if line and len(line) + 1 + len(token) > width:
            out.append(line)
            line = token
        else:
            line = f"{line} {token}".strip()
    if line:
        out.append(line)
    return out


#: Every SDK symbol this collector declares. Checked by `--check-sdk` so a
#: missing or renamed entry point is a named error rather than an AttributeError
#: raised mid-collection, three tables in.
REQUIRED_SYMBOLS = (
    "RfcOpenConnection", "RfcCloseConnection",
    "RfcGetFunctionDesc", "RfcCreateFunction", "RfcDestroyFunction", "RfcInvoke",
    "RfcSetChars", "RfcGetChars", "RfcGetTable", "RfcGetRowCount",
    "RfcMoveToFirstRow", "RfcMoveToNextRow", "RfcGetCurrentRow",
    "RfcAppendNewRow",
)


def check_sdk(home: Optional[str] = None) -> Dict[str, Any]:
    """Load the SDK and bind every symbol, WITHOUT connecting to anything.

    This is the first thing to run on a machine that has the SDK, and it is the
    honest version of a check `available()` cannot make: that function only asks
    whether a file exists at the expected path, which says nothing about whether
    it loads or whether the entry points this code declares are really in it.

    No host, no credential, no network. What it can catch: a wrong SAPNWRFC_HOME,
    an SDK whose siblings are not on the loader path, an architecture mismatch,
    and a symbol this binding names that the installed SDK version does not have.

    What it CANNOT catch is the shape of a call — argument order, struct layout,
    the RFC_READ_TABLE sequence. Those need a live system, and this collector has
    never been run against one.
    """
    # NO ctypes.c_wchar HERE, NOT EVEN TO MEASURE IT.
    # The first version reported the platform's wchar_t width as a diagnostic and
    # the test that forbids c_wchar in this file failed — correctly. An absolute
    # rule is worth more than the line it would have printed: a reader who sees
    # c_wchar mentioned anywhere has to work out whether THIS use is the safe one,
    # and the whole point is that nobody should have to.
    result: Dict[str, Any] = {"loaded": False, "path": None, "missing": [],
                              "sap_uc_bytes": 2}
    path = sdk_library_path(home)
    result["path"] = path
    lib = load_sdk(home)                       # raises RfcUnavailable with detail
    result["loaded"] = True
    result["missing"] = [name for name in REQUIRED_SYMBOLS
                         if not hasattr(lib, name)]
    return result


def available(home: Optional[str] = None) -> Tuple[bool, str]:
    """Whether an RFC collection could run here, and why not if it could not.

    Used by the CLI to report the situation before asking for a password, and by
    the tests, which must pass on machines with no SDK — which is all of CI.
    """
    try:
        path = sdk_library_path(home)
    except RfcUnavailable as exc:
        return False, str(exc)
    if not os.path.isfile(path):
        return False, f"no SDK library at {path}"
    return True, path
