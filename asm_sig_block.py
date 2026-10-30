#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
asm_sig_block.py - set selected ASM / Advanced WAF attack signatures to Blocking.

Disclaimer - Best-Effort Sample, Not Supported by F5
This script is provided by F5 Technical Support as a sample, "AS IS", on a best-effort basis,
without warranty of any kind. It is not an officially supported F5 product or feature. Writing
custom scripts and automation is normally done by F5 Professional Services and is outside the
scope of F5 Technical Support. You are responsible for reviewing it, testing it in a
non-production environment, and checking the results before you use it in production. F5
Support cannot maintain, enhance, customize, or troubleshoot this script, including modified
versions. Support can still help with problems in the underlying BIG-IP features or the
iControl REST API. For a solution that F5 fully designs and supports, contact your F5 account
team to engage F5 Professional Services.

What it does:
For each selected security policy, each listed signature is set to
    enabled = true, block = true, alarm = true, performStaging = false (unless --keep-staging)
Only fields that differ are changed. Changed policies are then applied.

Usage examples:
  ./asm_sig_block.py -H bigip.example.com -u admin --sig-file sigs.txt --dry-run
  ./asm_sig_block.py -H bigip.example.com -u admin --sigs 200001475,200000098
  ./asm_sig_block.py -H bigip.example.com -u admin --sigs 200001475 \\
      --policy-filter "/Common/prod_" --keep-staging
"""

import argparse
import contextlib
import csv
import getpass
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Union

import requests
import urllib3

POLICIES_PATH = "/mgmt/tm/asm/policies"
SIGNATURES_PATH = "/mgmt/tm/asm/signatures"
APPLY_PATH = "/mgmt/tm/asm/tasks/apply-policy"
EXPORT_PATH = "/mgmt/tm/asm/tasks/export-policy"
DOWNLOAD_PATH = "/mgmt/tm/asm/file-transfer/downloads"
DOWNLOAD_CHUNK = 512 * 1024

DISCLAIMER = (
    "Disclaimer - Best-Effort Sample, Not Supported by F5. "
    'This script is provided by F5 Technical Support as a sample, "AS IS", on a best-effort basis, '
    "without warranty of any kind. It is not an officially supported F5 product or feature. "
    "Writing custom scripts and automation is normally done by F5 Professional Services and is "
    "outside the scope of F5 Technical Support. You are responsible for reviewing it, testing it "
    "in a non-production environment, and checking the results before you use it in production. "
    "F5 Support cannot maintain, enhance, customize, or troubleshoot this script, including "
    "modified versions. Support can still help with problems in the underlying BIG-IP features "
    "or the iControl REST API. For a solution that F5 fully designs and supports, contact your "
    "F5 account team to engage F5 Professional Services."
)
BANNER = (
    "*** Best-effort sample, NOT supported by F5. Test in a non-production environment first. "
    "Contact your F5 account team for Professional Services. ***"
)

QUIET, NORMAL, VERBOSE = 0, 1, 2


class Output:
    """Tiny console writer with three levels (no logging config needed)."""

    level = NORMAL

    @classmethod
    def info(cls, msg: str = "") -> None:
        if cls.level >= NORMAL:
            print(msg)

    @classmethod
    def debug(cls, msg: str) -> None:
        if cls.level >= VERBOSE:
            print(f"    [v] {msg}")

    @staticmethod
    def warn(msg: str) -> None:
        print(msg)

    @staticmethod
    def error(msg: str) -> None:
        print(msg, file=sys.stderr)


out = Output

PAGE_SIZE = 100

EXIT_OK = 0
EXIT_ERRORS = 1
EXIT_USAGE = 2
EXIT_AUTH = 3


class BigIPError(RuntimeError):
    """An iControl REST call returned an HTTP error."""

    def __init__(self, method: str, path: str, status: int, text: str) -> None:
        self.method = method
        self.path = path
        self.status = status
        self.text = text
        super().__init__(f"{method} {path} -> HTTP {status}: {_error_message(text)}")


class AuthError(BigIPError):
    """The BIG-IP rejected the credentials (HTTP 401)."""


class FilterUnsupported(RuntimeError):
    """The policy-signature $filter was rejected or ignored by this BIG-IP version."""


class ConnectError(RuntimeError):
    """The BIG-IP could not be reached (DNS, TCP, TLS or timeout)."""


class BackupError(RuntimeError):
    """The policy could not be exported, so it is left unchanged."""


def _error_message(text: str) -> str:
    """Return the 'message' field of an iControl REST error body, or the raw text (truncated)."""
    try:
        msg = json.loads(text).get("message")
    except (ValueError, AttributeError):
        msg = None
    msg = msg or text
    return msg if len(msg) <= 300 else msg[:300] + "..."


class BigIP:
    """Minimal iControl REST client for the calls this script needs."""

    def __init__(self, host: str, verify: Union[bool, str] = False, retries: int = 3) -> None:
        self.base = f"https://{host}"
        self.retries = retries
        self.s = requests.Session()
        self.s.verify = verify
        self.s.headers.update({"Content-Type": "application/json"})
        self.token: Optional[str] = None

    def _send(
        self, method: str, path: str, retry: bool = False, **kwargs: Any
    ) -> requests.Response:
        """Send one request. With retry=True, retry connection errors and HTTP 5xx with backoff.

        Only safe calls (GET and the token login) use retry=True. PATCH/POST are never
        retried blindly: the caller re-reads the state and decides.
        """
        attempts = 1 + (self.retries if retry else 0)
        for attempt in range(1, attempts + 1):
            try:
                r = self._send_once(method, path, **kwargs)
            except ConnectError:
                if attempt == attempts:
                    raise
            else:
                if r.status_code < 500 or attempt == attempts:
                    return r
            delay = min(2 ** (attempt - 1), 30)
            out.warn(f"    [!] {method} {path} failed, retry {attempt}/{attempts - 1} in {delay}s")
            time.sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover

    def _send_once(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        try:
            r = self.s.request(method, f"{self.base}{path}", timeout=60, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as e:
            out.debug(f"{method} {path} -> connection error")
            raise ConnectError(f"cannot reach {self.base}: {e}") from e
        # Only method, path and status are logged; never bodies (they may hold credentials)
        out.debug(f"{method} {path} -> {r.status_code}")
        return r

    def login(self, username: str, password: str) -> None:
        """Get a token. If that fails, fall back to basic auth."""
        r = self._send(
            "POST",
            "/mgmt/shared/authn/login",
            retry=True,
            json={"username": username, "password": password, "loginProviderName": "tmos"},
        )
        if r.status_code == 200:
            self.token = r.json()["token"]["token"]
            self.s.headers["X-F5-Auth-Token"] = self.token
            # Extend the token timeout so long runs don't expire (max 36000 s)
            self._send("PATCH", f"/mgmt/shared/authz/tokens/{self.token}", json={"timeout": 7200})
        else:
            out.warn(f"[!] Token auth failed ({r.status_code}), using basic auth")
            self.s.auth = (username, password)

    def logout(self) -> None:
        """Delete the auth token, if one was issued. Never raises."""
        if not self.token:
            return
        with contextlib.suppress(ConnectError):
            self._send("DELETE", f"/mgmt/shared/authz/tokens/{self.token}")
        self.token = None
        self.s.headers.pop("X-F5-Auth-Token", None)

    def request(self, method: str, path: str, **kwargs: Any) -> Dict[str, Any]:
        """Send a request and return the JSON body. Raise BigIPError/AuthError on HTTP errors."""
        r = self._send(method, path, retry=(method == "GET"), **kwargs)
        if r.status_code == 401:
            raise AuthError(method, path, r.status_code, r.text)
        if not r.ok:
            raise BigIPError(method, path, r.status_code, r.text)
        return r.json() if r.content else {}

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.request("GET", path, params=params)

    def get_all(
        self, path: str, params: Optional[Dict[str, Any]] = None, page_size: int = PAGE_SIZE
    ) -> List[Dict[str, Any]]:
        """GET every item of a collection, page by page, using $top/$skip.

        Stops when a page is short, when totalItems is reached, or when a page adds no new
        items (protects against a server that ignores $skip).
        TODO(verify-on-bigip): default page size per version, and whether totalItems /
        nextLink are always present on /mgmt/tm/asm collections, including with $filter.
        """
        items: List[Dict[str, Any]] = []
        seen = set()
        skip = 0
        while True:
            page_params = dict(params or {}, **{"$top": page_size, "$skip": skip})
            data = self.get(path, params=page_params)
            page = data.get("items", [])
            new = [i for i in page if i.get("id") not in seen or i.get("id") is None]
            seen.update(i.get("id") for i in new)
            items.extend(new)
            skip += len(page)
            total = data.get("totalItems")
            if len(page) < page_size or not new or (total is not None and skip >= total):
                return items

    def download(self, path: str, dest: str, chunk: int = DOWNLOAD_CHUNK) -> int:
        """Download a file in chunks using the Content-Range header. Return the byte count.

        TODO(verify-on-bigip): Content-Range request/response format of
        /mgmt/tm/asm/file-transfer/downloads on each version.
        """
        written = 0
        with open(dest, "wb") as f:
            while True:
                end = written + chunk - 1
                headers = {"Content-Range": f"{written}-{end}/0"}
                r = self._send("GET", path, retry=True, headers=headers)
                if r.status_code == 401:
                    raise AuthError("GET", path, r.status_code, r.text)
                if not r.ok:
                    raise BigIPError("GET", path, r.status_code, r.text)
                f.write(r.content)
                written += len(r.content)
                total = _range_total(r.headers.get("Content-Range"))
                if not r.content or total is None or written >= total:
                    return written

    def patch(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("PATCH", path, json=body)

    def post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("POST", path, json=body)


def _range_total(header: Optional[str]) -> Optional[int]:
    """Return the total size from a 'start-end/total' Content-Range header, or None."""
    if not header or "/" not in header:
        return None
    try:
        return int(header.rsplit("/", 1)[1])
    except ValueError:
        return None


def parse_sig_ids(sigs: Optional[str], sig_file: Optional[str]) -> List[str]:
    """Collect signature IDs from a comma-separated string and/or a file.

    Returns a sorted, de-duplicated list. Exits with EXIT_USAGE if the file cannot be read or
    any ID is not numeric.
    """
    ids = set()
    if sigs:
        ids.update(s.strip() for s in sigs.split(",") if s.strip())
    if sig_file:
        try:
            with open(sig_file) as f:
                for line in f:
                    line = line.split("#")[0].strip()
                    if line:
                        ids.add(line)
        except OSError as e:
            out.error(f"[!] Cannot read signature file: {e}")
            sys.exit(EXIT_USAGE)
    bad = sorted(i for i in ids if not i.isdigit())
    if bad:
        out.error(f"[!] Invalid signature IDs (must be numeric): {bad}")
        sys.exit(EXIT_USAGE)
    return sorted(ids, key=int)


def load_sig_ids(args: argparse.Namespace) -> List[str]:
    """Compatibility wrapper around parse_sig_ids()."""
    return parse_sig_ids(args.sigs, args.sig_file)


def get_policies(
    bigip: BigIP, name_filter: Optional[str] = None, include_parent: bool = False
) -> List[Dict[str, Any]]:
    """List security policies, skipping parent policies unless asked, and apply the name filter."""
    policies = bigip.get_all(
        POLICIES_PATH, params={"$select": "id,name,fullPath,enforcementMode,type,parentPolicyName"}
    )
    if not include_parent:
        # Parent policies are not attached to traffic directly; skip by default
        policies = [p for p in policies if p.get("type", "security") != "parent"]
    if name_filter:
        policies = [p for p in policies if name_filter in p["fullPath"]]
    return policies


def lookup_signatures(bigip: BigIP, sig_ids: List[str]) -> Dict[str, Dict[str, str]]:
    """Look up each signature ID in the global signature list.

    Returns {signatureId: {"id": <global object id>, "name": <name>}} for the IDs that exist.
    IDs that are not found are left out.
    """
    found: Dict[str, Dict[str, str]] = {}
    for sid in sig_ids:
        data = bigip.get(
            SIGNATURES_PATH,
            params={"$filter": f"signatureId eq {sid}", "$select": "id,signatureId,name"},
        )
        for item in data.get("items", []):
            if str(item.get("signatureId")) == sid:
                found[sid] = {"id": item.get("id", ""), "name": item.get("name", "")}
                break
    return found


POLICY_SIG_SELECT = "id,enabled,block,alarm,learn,performStaging,signatureReference"


def reference_id(policy_sig: Dict[str, Any]) -> Optional[str]:
    """Return the global signature object ID from a policy signature's signatureReference.link.

    The link looks like https://localhost/mgmt/tm/asm/signatures/<id>?ver=<version>.
    TODO(verify-on-bigip): link format on 15.1, 16.1 and 17.x.
    """
    link = (policy_sig.get("signatureReference") or {}).get("link") or ""
    path = link.split("?", 1)[0].rstrip("/")
    if "/signatures/" not in path:
        return None
    return path.rsplit("/", 1)[-1] or None


def find_policy_signature(
    bigip: BigIP, policy_id: str, sig_id: str, global_id: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Return the policy-signature object for a global signatureId, or None.

    Raises FilterUnsupported if the BIG-IP rejects the filter, or ignores it (returns items
    for other signatures), so the caller can use the signatureReference fallback.
    """
    # TODO(verify-on-bigip): this $filter on the nested signature/signatureId field works on
    # each supported version (15.1, 16.1, 17.x), and the error returned when it does not.
    try:
        items = bigip.get_all(
            f"{POLICIES_PATH}/{policy_id}/signatures",
            params={"$filter": f"signature/signatureId eq {sig_id}", "$select": POLICY_SIG_SELECT},
        )
    except BigIPError as e:
        if e.status in (400, 501):
            raise FilterUnsupported(str(e)) from e
        raise
    if not items or global_id is None:
        return items[0] if items else None
    for item in items:
        if reference_id(item) == global_id:
            return item
    # Items came back but none is the requested signature: the filter was not honored.
    raise FilterUnsupported(f"filter returned {len(items)} unrelated item(s)")


def index_policy_signatures(bigip: BigIP, policy_id: str) -> Dict[str, Dict[str, Any]]:
    """Fallback: read all signatures of a policy once and index them by global signature ID."""
    items = bigip.get_all(
        f"{POLICIES_PATH}/{policy_id}/signatures", params={"$select": POLICY_SIG_SELECT}
    )
    return {rid: item for item in items if (rid := reference_id(item))}


ATTACK_SIG_VIOLATION_ID = "VIOL_ATTACK_SIGNATURE"
ATTACK_SIG_VIOLATION_DESC = "attack signature detected"


NO_BLOCK_FIELD = "no-block-field"


def attack_sig_violation_blocks(bigip: BigIP, policy_id: str) -> Union[bool, str, None]:
    """Report-only check: is "Attack signature detected" set to Block in this policy?

    Returns True/False, NO_BLOCK_FIELD if the entry was found without a block flag, or None if
    the entry was not found. Nothing is changed.
    The entry is matched on violationReference.name (on 21.1.0.2 the link ends in a generated ID,
    not the violation name), with the description text as a fallback. On 21.1.0.2 this entry
    never has block/alarm fields (collection, single-item GET and $select alike); the flags are
    kept per signature set instead, see signature_sets_not_blocking().
    TODO(verify-on-bigip): violationReference.name and whether block is returned on
    15.1/16.1/17.x, and whether a server-side $filter can be used instead of reading the list.
    """
    items = bigip.get_all(f"{POLICIES_PATH}/{policy_id}/blocking-settings/violations")
    for v in items:
        name = (v.get("violationReference") or {}).get("name")
        desc = str(v.get("description", "")).strip().lower()
        if name == ATTACK_SIG_VIOLATION_ID or desc == ATTACK_SIG_VIOLATION_DESC:
            block = v.get("block")
            return block if isinstance(block, bool) else NO_BLOCK_FIELD
    return None


def signature_sets_not_blocking(bigip: BigIP, policy_id: str) -> Optional[List[str]]:
    """Report-only: names of the policy's signature sets whose block flag is not true.

    Returns None if no signature set with a block flag was returned. Nothing is changed.
    TODO(verify-on-bigip): signature-sets block/alarm fields on 15.1/16.1/17.x (confirmed on
    21.1.0.2).
    """
    items = bigip.get_all(f"{POLICIES_PATH}/{policy_id}/signature-sets")
    with_flag = [i for i in items if isinstance(i.get("block"), bool)]
    if not with_flag:
        return None
    return [
        str((i.get("signatureSetReference") or {}).get("name") or i.get("id"))
        for i in with_flag
        if not i["block"]
    ]


def is_inheritance_error(err: BigIPError) -> bool:
    """Return True if a PATCH error looks like "this setting is inherited from the parent".

    TODO(verify-on-bigip): capture the exact status code and message returned when patching an
    inherited signature on a child policy, and tighten this check.
    """
    return err.status in (400, 403, 409) and "inherit" in err.text.lower()


def parent_name(pol: Dict[str, Any]) -> Optional[str]:
    """Return the parent policy's fullPath / name if the policy object includes it."""
    # TODO(verify-on-bigip): whether parentPolicyName is returned with the $select used here.
    return pol.get("parentPolicyName") or None


def desired_state(keep_staging: bool) -> Dict[str, bool]:
    """Return the target field values for each signature."""
    desired = {"enabled": True, "block": True, "alarm": True}
    if not keep_staging:
        desired["performStaging"] = False
    return desired


def compute_diff(policy_sig: Dict[str, Any], desired: Dict[str, bool]) -> Dict[str, bool]:
    """Return only the fields whose current value differs from the desired value."""
    return {k: v for k, v in desired.items() if policy_sig.get(k) != v}


REPORT_COLUMNS = ["policy", "signature_id", "signature_name", "action", "before", "after", "error"]


def format_state(policy_sig: Dict[str, Any], fields: List[str]) -> str:
    """Render the given fields as 'enabled=true;block=false;...' for the CSV report."""
    return ";".join(f"{k}={json.dumps(policy_sig.get(k))}" for k in fields)


def write_report(path: str, rows: List[Dict[str, str]]) -> None:
    """Write the per-signature results to a CSV file."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def wait_for_task(
    bigip: BigIP, path: str, task_id: str, timeout: float
) -> Optional[Dict[str, Any]]:
    """Poll an ASM task until COMPLETED or FAILURE. Return the task, or None on timeout.

    TODO(verify-on-bigip): task status values (NEW, RUNNING, COMPLETED, FAILURE) per version.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        task = bigip.get(f"{path}/{task_id}")
        if task.get("status") in ("COMPLETED", "FAILURE"):
            return task
        time.sleep(3)
    return None


def apply_policy(bigip: BigIP, policy_id: str, policy_name: str, timeout: float = 300) -> bool:
    """Start an apply-policy task and wait for it. Return True if it completed."""
    task = bigip.post(
        APPLY_PATH,
        {"policyReference": {"link": f"https://localhost{POLICIES_PATH}/{policy_id}"}},
    )
    result = wait_for_task(bigip, APPLY_PATH, task["id"], timeout)
    if result is None:
        out.warn(f"    [!] Apply timed out for '{policy_name}'")
        return False
    if result.get("status") == "FAILURE":
        out.warn(f"    [!] Apply FAILED for '{policy_name}'")
        return False
    out.info(f"    [+] Policy '{policy_name}' applied")
    return True


def backup_filename(policy_name: str) -> str:
    """Build a safe export file name from a policy fullPath, e.g. Common_app1_<time>.xml."""
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in policy_name.strip("/"))
    return f"{safe}_{time.strftime('%Y%m%d-%H%M%S')}.xml"


def export_policy(
    bigip: BigIP, policy_id: str, policy_name: str, backup_dir: str, timeout: float = 300
) -> str:
    """Export a policy as XML on the BIG-IP and download it into backup_dir. Return the path.

    TODO(verify-on-bigip): export-policy task body (filename, policyReference) and that the
    exported file is served by /mgmt/tm/asm/file-transfer/downloads/<filename>.
    """
    filename = backup_filename(policy_name)
    task = bigip.post(
        EXPORT_PATH,
        {
            "filename": filename,
            "policyReference": {"link": f"https://localhost{POLICIES_PATH}/{policy_id}"},
        },
    )
    result = wait_for_task(bigip, EXPORT_PATH, task["id"], timeout)
    if result is None:
        raise BackupError("export task timed out")
    if result.get("status") == "FAILURE":
        raise BackupError(f"export task failed: {result.get('result') or ''}")
    dest = os.path.join(backup_dir, filename)
    size = bigip.download(f"{DOWNLOAD_PATH}/{filename}", dest)
    if size == 0:
        raise BackupError("exported file is empty")
    return dest


class Runner:
    """Process every (policy, signature) pair and keep the summary counts."""

    def __init__(
        self, bigip: BigIP, args: argparse.Namespace, sigs: Dict[str, Dict[str, str]]
    ) -> None:
        self.bigip = bigip
        self.args = args
        self.sigs = sigs
        self.sig_ids = sorted(sigs, key=int)
        self.desired = desired_state(args.keep_staging)
        self.summary = {
            "changed": 0,
            "would_change": 0,
            "already": 0,
            "missing": 0,
            "skipped": 0,
            "errors": 0,
        }

        self.rows: List[Dict[str, str]] = []
        self.policy = ""

        self.use_filter = True
        self.parent: Optional[str] = None
        self._backed_up: Dict[str, str] = {}
        self._backup_failed: Dict[str, str] = {}
        self._index: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def find(self, pid: str, sid: str) -> Optional[Dict[str, Any]]:
        """Find a signature in a policy, switching to the reference-link fallback if needed."""
        global_id = self.sigs.get(sid, {}).get("id") or None
        if self.use_filter:
            try:
                return find_policy_signature(self.bigip, pid, sid, global_id)
            except FilterUnsupported as e:
                if not global_id:
                    raise
                out.warn(
                    f"    [i] Policy-signature $filter not usable on this BIG-IP ({e}); "
                    "matching on signatureReference instead (slower)"
                )
                self.use_filter = False
        if pid not in self._index:
            self._index = {pid: index_policy_signatures(self.bigip, pid)}
        return self._index[pid].get(global_id)  # type: ignore[arg-type]

    def preflight(self, pid: str) -> None:
        """Warn (only) if the "Attack signature detected" violation is not set to Block."""
        try:
            blocks = attack_sig_violation_blocks(self.bigip, pid)
        except AuthError:
            raise
        except (BigIPError, ConnectError) as e:
            out.warn(f"    [i] Could not read blocking settings (report only): {e}")
            return
        if blocks == NO_BLOCK_FIELD:
            self.preflight_signature_sets(pid)
        elif blocks is None:
            out.warn(
                "    [i] Could not confirm the 'Attack signature detected' Block flag "
                "(not found in blocking settings)"
            )
        elif not blocks:
            out.warn(
                "    [i] NOTE: 'Attack signature detected' violation is NOT set to Block in this "
                "policy, so signatures will not block. This script does not change it."
            )
        else:
            out.debug("'Attack signature detected' violation is set to Block")

    def preflight_signature_sets(self, pid: str) -> None:
        """Fallback when the violation entry has no block flag: check the signature sets."""
        try:
            not_blocking = signature_sets_not_blocking(self.bigip, pid)
        except AuthError:
            raise
        except (BigIPError, ConnectError) as e:
            out.warn(f"    [i] Could not read signature sets (report only): {e}")
            return
        if not_blocking is None:
            out.warn(
                "    [i] Could not confirm the 'Attack signature detected' Block flag "
                "(the BIG-IP did not return it). Check it in the GUI."
            )
        elif not_blocking:
            out.warn(
                "    [i] NOTE: these signature sets are NOT set to Block in this policy, so their "
                f"signatures will not block: {', '.join(not_blocking)}. This script does not "
                "change them."
            )
        else:
            out.debug("All signature sets in the policy are set to Block")

    def record(
        self,
        sid: str,
        action: str,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        error: str = "",
    ) -> None:
        """Add one row to the CSV report (kept in memory, written at the end)."""
        fields = list(self.desired)
        self.rows.append(
            {
                "policy": self.policy,
                "signature_id": sid,
                "signature_name": self.sigs.get(sid, {}).get("name", ""),
                "action": action,
                "before": format_state(before, fields) if before is not None else "",
                "after": format_state(after, fields) if after is not None else "",
                "error": error,
            }
        )

    def ensure_backup(self, pid: str) -> None:
        """Export the policy once before its first change (--backup-dir). Raise BackupError."""
        if not self.args.backup_dir or pid in self._backed_up:
            return
        if pid in self._backup_failed:
            raise BackupError(f"backup failed, policy not changed ({self._backup_failed[pid]})")
        try:
            path = export_policy(
                self.bigip, pid, self.policy, self.args.backup_dir, self.args.apply_timeout
            )
        except AuthError:
            raise
        except (BigIPError, ConnectError, BackupError, KeyError, OSError) as e:
            self._backup_failed[pid] = str(e)
            raise BackupError(f"backup failed, policy not changed ({e})") from e
        self._backed_up[pid] = path
        out.info(f"    [*] Policy exported to {path}")

    def label(self, sid: str) -> str:
        name = self.sigs.get(sid, {}).get("name")
        return f"{sid} ({name})" if name else sid

    def process_signature(self, pid: str, sid: str) -> bool:
        """Bring one signature in one policy to the desired state. Return True if patched."""
        ps = self.find(pid, sid)
        if not ps:
            out.info(f"    [-] {self.label(sid)}: not in this policy's signature sets")
            self.summary["missing"] += 1
            self.record(sid, "missing")
            return False

        diff = compute_diff(ps, self.desired)
        if not diff:
            out.info(f"    [=] {self.label(sid)}: already blocking")
            self.summary["already"] += 1
            self.record(sid, "already", ps, ps)
            return False

        if self.args.dry_run:
            out.info(f"    [~] {self.label(sid)}: would set {diff}")
            self.summary["would_change"] += 1
            self.record(sid, "would_change", ps, {**ps, **diff})
            return False

        self.ensure_backup(pid)
        try:
            self.bigip.patch(f"{POLICIES_PATH}/{pid}/signatures/{ps['id']}", diff)
        except BigIPError as e:
            if not is_inheritance_error(e):
                raise
            parent = self.parent or "its parent policy"
            out.warn(
                f"    [!] {self.label(sid)}: setting is inherited from {parent}; "
                "use --include-parent or change the parent policy"
            )
            self.summary["errors"] += 1
            self.record(sid, "error", ps, error=f"inherited from {parent}: {e}")
            return False
        out.info(f"    [+] {self.label(sid)}: updated {diff}")
        self.summary["changed"] += 1
        self.record(sid, "changed", ps, {**ps, **diff})
        return True

    def process_policy(self, pol: Dict[str, Any]) -> None:
        pid, pname = pol["id"], pol["fullPath"]
        self.policy = pname
        self.parent = parent_name(pol)
        out.info(f"[*] Policy: {pname}  (enforcement: {pol.get('enforcementMode')})")
        if pol.get("enforcementMode") != "blocking":
            out.warn(
                f"    [i] NOTE: policy is in {pol.get('enforcementMode')} mode, "
                "so signature blocking has no effect until it is set to blocking"
            )

        self.preflight(pid)

        changed = False
        for sid in self.sig_ids:
            try:
                if self.process_signature(pid, sid):
                    changed = True
            except AuthError:
                raise
            except (
                BigIPError,
                ConnectError,
                FilterUnsupported,
                BackupError,
                KeyError,
                ValueError,
            ) as e:
                out.warn(f"    [!] {self.label(sid)}: error in policy {pname}: {e}")
                self.summary["errors"] += 1
                self.record(sid, "error", error=str(e))

        if changed and not self.args.no_apply:
            try:
                ok = apply_policy(self.bigip, pid, pname, self.args.apply_timeout)
            except AuthError:
                raise
            except (BigIPError, ConnectError, KeyError) as e:
                out.warn(f"    [!] Apply of policy {pname} could not be started: {e}")
                ok = False
            if not ok:
                self.summary["errors"] += 1
                self.record("", "error", error="apply-policy failed or timed out")
        out.info()

    def run(self, policies: List[Dict[str, Any]]) -> Dict[str, int]:
        for pol in policies:
            self.process_policy(pol)
        return self.summary


def print_summary(summary: Dict[str, int], dry_run: bool) -> None:
    print("=== Summary ===")
    for k, v in summary.items():
        print(f"  {k:12}: {v}")
    if dry_run:
        print("  (dry run: nothing was changed)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Set selected ASM signatures to blocking in all policies",
        epilog=DISCLAIMER,
    )
    ap.add_argument("-H", "--host", required=True, help="BIG-IP management IP/hostname")
    ap.add_argument("-u", "--user", required=True)
    ap.add_argument(
        "-p",
        "--password",
        help="Password. If omitted, the F5_PASSWORD environment variable is used, "
        "otherwise you are prompted (recommended)",
    )
    tls = ap.add_mutually_exclusive_group()
    tls.add_argument(
        "--verify",
        action="store_true",
        help="Verify the BIG-IP management certificate against the system CA store",
    )
    tls.add_argument(
        "--ca-bundle",
        metavar="PATH",
        help="Verify the BIG-IP management certificate against this CA bundle file",
    )
    ap.add_argument(
        "--retries",
        type=int,
        default=3,
        metavar="N",
        help="Retries for GET and login on connection errors / HTTP 5xx (default: 3)",
    )
    ap.add_argument("--sigs", help="Comma-separated signature IDs (e.g. 200001475,200000098)")
    ap.add_argument("--sig-file", help="File with one signature ID per line")
    ap.add_argument("--policy-filter", help="Only policies whose fullPath contains this string")
    ap.add_argument(
        "--include-parent",
        action="store_true",
        help="Also process parent policies (skipped by default)",
    )
    ap.add_argument(
        "--keep-staging",
        action="store_true",
        help="Do NOT disable staging (default: staging is turned off)",
    )
    ap.add_argument(
        "--report",
        metavar="FILE.csv",
        help="Write one CSV row per policy/signature with the action taken",
    )
    ap.add_argument(
        "--backup-dir",
        metavar="DIR",
        help="Export each policy (XML) into DIR before changing it. "
        "A policy whose export fails is not changed",
    )
    ap.add_argument("--no-apply", action="store_true", help="Modify but don't apply policies")
    ap.add_argument(
        "--apply-timeout",
        type=int,
        default=300,
        metavar="SECONDS",
        help="How long to wait for each apply-policy task (default: 300)",
    )
    ap.add_argument("--dry-run", action="store_true", help="Show what would change, change nothing")
    verbosity = ap.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-q", "--quiet", action="store_true", help="Only print warnings, errors and the summary"
    )
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Also log each HTTP request (method, path, status code; never bodies)",
    )
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    out.level = QUIET if args.quiet else VERBOSE if args.verbose else NORMAL
    out.info(BANNER + "\n")

    if args.retries < 0:
        out.error("[!] --retries must be 0 or more")
        return EXIT_USAGE
    if args.apply_timeout <= 0:
        out.error("[!] --apply-timeout must be more than 0")
        return EXIT_USAGE
    sig_ids = parse_sig_ids(args.sigs, args.sig_file)
    if not sig_ids:
        out.error("[!] No signature IDs supplied (use --sigs and/or --sig-file)")
        return EXIT_USAGE

    if args.report and not report_writable(args.report):
        return EXIT_USAGE
    if args.backup_dir and not backup_dir_ready(args.backup_dir):
        return EXIT_USAGE

    password = get_password(args)
    bigip = BigIP(args.host, verify=tls_verify(args), retries=args.retries)
    try:
        return run(bigip, args, password, sig_ids)
    finally:
        bigip.logout()


def report_writable(path: str) -> bool:
    """Check early that the report file can be created, so a long run doesn't fail at the end."""
    try:
        with open(path, "a", encoding="utf-8"):
            pass
    except OSError as e:
        out.error(f"[!] Cannot write report file: {e}")
        return False
    return True


def backup_dir_ready(path: str) -> bool:
    """Create the backup directory if needed. Return False (with a message) if that fails."""
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        out.error(f"[!] Cannot create backup directory: {e}")
        return False
    return True


def get_password(args: argparse.Namespace) -> str:
    """Return the password from --password, then F5_PASSWORD, then an interactive prompt."""
    return (
        args.password
        or os.environ.get("F5_PASSWORD")
        or getpass.getpass(f"Password for {args.user}@{args.host}: ")
    )


def tls_verify(args: argparse.Namespace) -> Union[bool, str]:
    """Return the requests 'verify' value. Warn and silence urllib3 when not verifying."""
    if args.ca_bundle:
        if not os.path.isfile(args.ca_bundle):
            out.error(f"[!] CA bundle not found: {args.ca_bundle}")
            sys.exit(EXIT_USAGE)
        return args.ca_bundle
    if args.verify:
        return True
    out.warn(
        "[!] TLS certificate verification is OFF (common for self-signed management certs). "
        "Use --verify or --ca-bundle PATH to turn it on."
    )
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return False


def run(bigip: BigIP, args: argparse.Namespace, password: str, sig_ids: List[str]) -> int:
    """Log in, process all policies and print the summary. Return the exit code."""
    try:
        bigip.login(args.user, password)
        sigs = check_signatures(bigip, sig_ids)
        if not sigs:
            out.error(
                "[!] None of the requested signature IDs exist on this BIG-IP. Nothing to do."
            )
            return EXIT_USAGE
        policies = get_policies(bigip, args.policy_filter, args.include_parent)
    except AuthError:
        out.error(f"[!] Authentication failed for user '{args.user}' on {args.host}")
        return EXIT_AUTH
    except ConnectError as e:
        out.error(f"[!] Connection failed: {e}")
        return EXIT_AUTH
    except BigIPError as e:
        out.error(f"[!] Could not read signatures or policies: {e}")
        return EXIT_ERRORS
    out.info(f"[*] {len(policies)} policies, {len(sigs)} signatures to process\n")

    runner = Runner(bigip, args, sigs)
    for sid in sig_ids:
        if sid not in sigs:
            runner.summary["skipped"] += 1
            runner.record(sid, "skipped", error="signature ID not found on this BIG-IP")
    try:
        summary = runner.run(policies)
    except AuthError as e:
        out.error(f"[!] Authentication was rejected during the run: {e}")
        return EXIT_AUTH
    except ConnectError as e:
        out.error(f"[!] Connection lost during the run: {e}")
        return EXIT_AUTH
    finally:
        if args.report:
            write_report(args.report, runner.rows)
            out.info(f"[*] Report written to {args.report}")
    print_summary(summary, args.dry_run)
    return EXIT_ERRORS if summary["errors"] or summary["skipped"] else EXIT_OK


def check_signatures(bigip: BigIP, sig_ids: List[str]) -> Dict[str, Dict[str, str]]:
    """Look up all requested IDs, print their names, and warn once about unknown IDs."""
    sigs = lookup_signatures(bigip, sig_ids)
    out.info("[*] Signatures:")
    for sid in sig_ids:
        if sid in sigs:
            out.info(f"    {sid}  {sigs[sid]['name']}")
        else:
            out.warn(f"    [!] {sid}: not found on this BIG-IP (check the ID); it will be skipped")
    out.info()
    return sigs


if __name__ == "__main__":
    sys.exit(main())
