# asm-sig-block

> [!CAUTION]
> **Disclaimer — Best-Effort Sample, Not Supported by F5**
>
> This script is provided by F5 Technical Support as a sample, "AS IS", on a best-effort basis, without
> warranty of any kind. It is not an officially supported F5 product or feature. Writing custom scripts and
> automation is normally done by F5 Professional Services and is outside the scope of F5 Technical Support.
> You are responsible for reviewing it, testing it in a non-production environment, and checking the results
> before you use it in production. F5 Support cannot maintain, enhance, customize, or troubleshoot this
> script, including modified versions. Support can still help with problems in the underlying BIG-IP features
> or the iControl REST API. For a solution that F5 fully designs and supports, contact your F5 account
> team to engage F5 Professional Services.

`asm_sig_block.py` sets a chosen list of BIG-IP ASM / Advanced WAF attack signatures (by signature ID)
to **Blocking** in all security policies, or in a filtered set of them, using the iControl REST API.
Then it applies the changed policies.

## Contents

- [What it does](#what-it-does)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Preparing the signature list](#preparing-the-signature-list)
- [Usage](#usage)
- [Sample output](#sample-output)
- [Recommended rollout](#recommended-rollout)
- [Things to keep in mind](#things-to-keep-in-mind)
- [Verification](#verification)
- [Rollback](#rollback)
- [Support](#support)
- [License](#license)

## What it does

1. Logs in to the BIG-IP and gets an auth token (falls back to basic auth if token login is not
   available). The token is deleted at the end of the run.
2. Looks up each signature ID in the BIG-IP's global signature list and shows its name. IDs that do
   not exist are reported once and skipped.
3. Lists the security policies. Parent policies are skipped unless `--include-parent` is given, and
   `--policy-filter` narrows the list.
4. For each policy:
   - warns if the policy is not in blocking mode, or if the "Attack signature detected" violation is
     not set to Block (on versions where that flag is kept per signature set, such as 21.1, it
     checks the policy's signature sets instead). Report only; the script never changes these;
   - finds each signature in the policy and sets it to
     `enabled = true`, `block = true`, `alarm = true`, `performStaging = false`
     (staging is left as-is with `--keep-staging`). Only the fields that differ are changed;
   - optionally exports the policy first (`--backup-dir`);
   - applies the policy if anything changed (unless `--no-apply` or `--dry-run`).
5. Prints a summary, and optionally writes a CSV report (`--report`).

The script does **not** change enforcement mode, signature sets, or violation blocking settings.
It runs one step at a time to keep the load on the control plane low.

## Prerequisites

| Item | Requirement |
|---|---|
| Where to run it | A workstation or jump host, **not** on the BIG-IP itself |
| Python | 3.8 or later |
| Python packages | `requests` (see `requirements.txt`) |
| Network | HTTPS (TCP 443) from the workstation to the BIG-IP management address |
| BIG-IP account | Role **Administrator** or **Application Security Administrator**, with access to every partition that holds the policies |
| BIG-IP modules | ASM / Advanced WAF provisioned |

## Installation

Get the code (clone the repository, or download and unzip it), then create a virtual environment.

**Linux / macOS**

```bash
cd asm-sig-block
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python asm_sig_block.py --help
```

**Windows (PowerShell)**

```powershell
cd asm-sig-block
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python asm_sig_block.py --help
```

## Preparing the signature list

Pass signature IDs with `--sigs` (comma-separated), with `--sig-file` (one ID per line, `#` starts a
comment), or both. Only numeric IDs are accepted.

```text
# signatures to block
200001475
200000098   # comments may follow an ID
```

**Find signature IDs in the GUI:** **Security > Options > Application Security > Attack Signatures**.
Search by name or ID. The **ID** column is the signature ID.

**Find signature IDs with REST:**

```bash
curl -sk -u admin "https://bigip.example.com/mgmt/tm/asm/signatures?\$filter=signatureId%20eq%20200001475&\$select=signatureId,name"
```

## Usage

```text
python asm_sig_block.py -H HOST -u USER [options]
```

| Option | Description |
|---|---|
| `-H`, `--host` | BIG-IP management IP or hostname (required) |
| `-u`, `--user` | User name (required) |
| `-p`, `--password` | Password. If omitted, `F5_PASSWORD` is used, otherwise you are prompted (recommended) |
| `--sigs` | Comma-separated signature IDs |
| `--sig-file` | File with one signature ID per line |
| `--policy-filter` | Only policies whose full path contains this text, e.g. `/Common/prod_` |
| `--include-parent` | Also process parent policies (skipped by default) |
| `--keep-staging` | Leave staging as-is (by default staging is turned off) |
| `--dry-run` | Show what would change; change nothing |
| `--no-apply` | Change the policies but do not apply them |
| `--apply-timeout SECONDS` | How long to wait for each apply (and export) task. Default 300 |
| `--backup-dir DIR` | Export each policy (XML) into `DIR` before its first change. A policy whose export fails is not changed |
| `--report FILE.csv` | Write one CSV row per policy and signature |
| `--verify` | Check the management certificate against the system CA store |
| `--ca-bundle PATH` | Check the management certificate against this CA bundle |
| `--retries N` | Retries for GET requests and login on connection errors / HTTP 5xx. Default 3 |
| `-q`, `--quiet` | Only print warnings, errors and the summary |
| `-v`, `--verbose` | Also log each HTTP request (method, path, status code; never bodies) |

### Examples

```bash
# 1. Dry run against all policies: nothing is changed
python asm_sig_block.py -H bigip.example.com -u admin --sig-file sigs.txt --dry-run

# 2. Pilot on a few policies, with a backup and a report
python asm_sig_block.py -H bigip.example.com -u admin --sig-file sigs.txt \
    --policy-filter "/Common/app1_" --backup-dir backups --report pilot.csv

# 3. Change the policies but apply them later yourself (for example, in the GUI)
python asm_sig_block.py -H bigip.example.com -u admin --sig-file sigs.txt --no-apply

# 4. Full run, keeping staging as-is
python asm_sig_block.py -H bigip.example.com -u admin --sigs 200001475,200000098 \
    --keep-staging --backup-dir backups --report full-run.csv
```

To avoid typing the password, set `F5_PASSWORD` for the current shell only
(`read -s F5_PASSWORD; export F5_PASSWORD` on Linux/macOS). Avoid `-p` on shared systems, because
command lines can be seen by other users and are kept in shell history.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Some errors (a signature or apply failed, or an ID was not found on the BIG-IP) |
| 2 | Bad usage or input (invalid IDs, unreadable file, none of the IDs exist on the BIG-IP) |
| 3 | Authentication or connection failure |

### CSV report

Columns: `policy,signature_id,signature_name,action,before,after,error`.
`action` is one of `changed`, `would_change`, `already`, `missing`, `error`, `skipped`.
`before` and `after` show the signature's fields, e.g. `enabled=true;block=false;alarm=true;performStaging=true`.
The report is written even if the run is stopped early.

## Sample output

A dry run. The policy and signature names are examples only.

```text
*** Best-effort sample, NOT supported by F5. Test in a non-production environment first. Contact your F5 account team for Professional Services. ***

[!] TLS certificate verification is OFF (common for self-signed management certs). Use --verify or --ca-bundle PATH to turn it on.
[*] Signatures:
    200000098  Example signature B
    200001475  Example signature A
    [!] 200099999: not found on this BIG-IP (check the ID); it will be skipped

[*] 2 policies, 2 signatures to process

[*] Policy: /Common/app1_policy  (enforcement: blocking)
    [=] 200000098 (Example signature B): already blocking
    [~] 200001475 (Example signature A): would set {'block': True, 'performStaging': False}

[*] Policy: /Common/app2_policy  (enforcement: transparent)
    [i] NOTE: policy is in transparent mode, so signature blocking has no effect until it is set to blocking
    [i] NOTE: these signature sets are NOT set to Block in this policy, so their signatures will not block: Generic Detection Signatures. This script does not change them.
    [-] 200000098 (Example signature B): not in this policy's signature sets
    [~] 200001475 (Example signature A): would set {'block': True, 'performStaging': False}

=== Summary ===
  changed     : 0
  would_change: 2
  already     : 1
  missing     : 1
  skipped     : 1
  errors      : 0
  (dry run: nothing was changed)
```

Line markers: `[+]` changed, `[~]` would change, `[=]` already as wanted, `[-]` not in the policy,
`[!]` warning or error, `[i]` information.

## Recommended rollout

1. **Back up.** Create a UCS archive (**System > Archives**) and export the affected policies
   (**Security > Application Security > Security Policies > Policies List**, or `--backup-dir`).
2. **Test in a lab** BIG-IP on the same version, with a copy of the policies if possible.
3. **Dry run** against production with `--dry-run --report dry-run.csv` and review the report.
4. **Check for false positives before you remove staging.** Look in
   **Security > Event Logs > Application > Requests** for requests that these signatures would block.
   Requests that are legitimate will be blocked once staging is off and Block is on. If you are not
   sure, use `--keep-staging` first.
5. **Pilot** on one or a few policies with `--policy-filter`.
6. **Run in a change window**, with `--backup-dir` and `--report`.
7. **Sync HA devices.** If the device group uses manual sync, sync the configuration to the peers
   (**Device Management > Overview**).
8. **Monitor** the request log and application owners' feedback for blocked legitimate traffic.

## Things to keep in mind

- **The signature must already be in the policy's signature sets.** If it is not, the script reports
  it as `missing` and does not add it. Change the policy's signature sets if needed.
- **Transparent policies do not block.** Blocking settings have no effect until the policy's
  enforcement mode is Blocking. The script warns but does not change it.
- **Attack signatures must have Block turned on** in the policy's blocking settings, or
  signatures only alarm. On older versions this is the Block flag of the "Attack signature detected"
  violation. On 21.1 it is set per signature set (the REST API returns no Block flag on the
  violation), and the script lists any signature set that is not set to Block. Clearing Block on a
  signature set also clears it on that set's signatures. The script warns but does not change these.
- **Staging is turned off by default.** Staged signatures never block. Use `--keep-staging` to leave
  staging as it is.
- **Parent and child policies.** A child policy may inherit signature settings from its parent. A
  change to such a signature in the child is rejected; the script reports it and you can use
  `--include-parent` or change the parent policy.
- **Control plane load.** Every apply-policy task uses control plane CPU. Run large changes in a
  maintenance window. Use `--no-apply` to change many policies and apply them later in a controlled way.
- **Partitions.** The account must be able to see and change policies in every partition involved.
  Policies the account cannot see are not processed.
- **TLS.** Certificate checks are off by default because management certificates are often
  self-signed. Use `--verify` or `--ca-bundle` if the management certificate is trusted.
- **Token lifetime.** The token timeout is extended to 2 hours. Very long runs may need to be split
  with `--policy-filter`.
- **Audit log.** Changes appear in the BIG-IP audit log under the account the script uses.
- **Attack signature updates (ASU).** An update can add new signatures (which follow the policy's
  staging settings) and can change existing ones. After an update, run a dry run again to confirm
  that your signatures are still as expected, and add any new IDs to your list.

## Verification

**GUI:** **Security > Application Security > Attack Signatures**, select the policy, search for the
signature ID, and check that it is **Enabled**, **Block** is checked, and it is **not** in staging.
Check that the policy shows no unapplied changes.

**REST:**

```bash
curl -sk -u admin "https://bigip.example.com/mgmt/tm/asm/policies/<policy-id>/signatures?\$filter=signature/signatureId%20eq%20200001475&\$select=enabled,block,alarm,performStaging"
```

Get the `<policy-id>` from `GET /mgmt/tm/asm/policies?$select=id,fullPath`. A dry run after the
change should report every signature as `already`.

## Rollback

Test these steps in a lab first. They assume you made a backup before the run (UCS archive, policy
export, or `--backup-dir`) and kept the `--report` CSV, whose `before` column shows each signature's
earlier state.

1. **A few signatures, in the GUI.** Go to **Security > Application Security > Attack Signatures**,
   select the policy, find the signature by ID, and set it back to its `before` values (staging on,
   Block off, or disabled). Click **Apply Policy**.
2. **A few signatures, with REST.**

   ```bash
   # Find the policy ID and the policy-signature ID
   curl -sk -u admin "https://bigip.example.com/mgmt/tm/asm/policies?\$select=id,fullPath"
   curl -sk -u admin "https://bigip.example.com/mgmt/tm/asm/policies/<policy-id>/signatures?\$filter=signature/signatureId%20eq%20200001475&\$select=id,enabled,block,alarm,performStaging"

   # Change it back, then apply the policy
   curl -sk -u admin -X PATCH -H "Content-Type: application/json" \
     -d '{"block": false, "performStaging": true}' \
     "https://bigip.example.com/mgmt/tm/asm/policies/<policy-id>/signatures/<policy-signature-id>"
   curl -sk -u admin -X POST -H "Content-Type: application/json" \
     -d '{"policyReference": {"link": "https://localhost/mgmt/tm/asm/policies/<policy-id>"}}' \
     "https://bigip.example.com/mgmt/tm/asm/tasks/apply-policy"
   ```

3. **A whole policy.** Go to **Security > Application Security > Security Policies > Policies List >
   Import Policy**, choose the XML file from `--backup-dir` (or your own export), replace the existing
   policy, and apply it. This also undoes any other change made to the policy after the export.
4. **Last resort: the UCS archive.** This restores the whole BIG-IP configuration, not just ASM, and
   undoes every change since the archive was made. Plan it in a change window.

After any rollback, sync HA peers if the device group uses manual sync, and run the script with
`--dry-run --report check.csv` to confirm the state of each signature.

## Support

This is a best-effort sample and is not supported by F5 (see the disclaimer at the top).

- If BIG-IP or the iControl REST API itself behaves incorrectly, open a case with F5 Support.
- For a solution that F5 designs and supports, contact your F5 account team to engage
  F5 Professional Services.
- Issues in this repository are answered on a best-effort basis only.

## License

Licensed under the [Apache License 2.0](LICENSE). The license does not change the disclaimer at the
top of this README: this is a best-effort sample, not supported by F5.
