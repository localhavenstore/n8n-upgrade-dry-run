# n8n Upgrade Dry-Run

Run **copies** of your n8n workflows on your current n8n version and on the version you want to upgrade to, and see
**node by node** what changes - before you upgrade the real thing.

n8n 3.0 removes old nodes and changes some behaviour (n8n's
[v3.0 breaking-changes page](https://docs.n8n.io/changelog/v30-breaking-changes/)). Some changes only show when a
workflow actually runs - for example, If/Switch nodes with "Always Output Data" now add an empty item only when *every*
output is empty, so a branch that ran before may not run any more. A static checker cannot see that; running both
versions side by side can.

```
n8n export:workflow --all --output=workflows.json          # on your n8n (read-only)
python3 dryrun.py --workflows workflows.json --old n8nio/n8n:2.42.3 --new n8nio/n8n:<new-version>
```

Output: `dryrun-report/report.md` + `report.json`.

## What it does
1. Makes **copies** of your exported workflows. Your n8n is never touched - the input is the export file.
2. Starts one throw-away container per workflow and version (gVisor runtime, **no network**, all capabilities dropped,
   read-only root, CPU/memory/process limits). The export is mounted read-only and deleted afterwards.
3. Runs each workflow with `n8n execute` on both images and compares **every run of every node, every output branch**
   (JSON + binary metadata and content hash).
4. Adds static checks for the n8n 3.0 changes: removed nodes, AI Agent v1 old modes, Gmail Trigger below 1.4, If/Switch
   "Always Output Data", sub-workflows from files/URLs, Execute Command (the 3.0 image has no package manager),
   Code steps over 60 s, unverified community packages.

Results per node: `SAME`, `CHANGED`, `NOT-RUN-NEW` (no longer reached), `ERROR-NEW`, `FAILED-NEW`, ... and the
opposite cases. The exit code is 0 only if **every** workflow ran on both versions and **every** node gave the same output.

## Honest limits
- **One test run per workflow, without network.** Nodes that call external services show `blocked (no network)`; their
  behaviour after the upgrade is not tested. Pinned data in your workflows is used as test input - pin realistic data.
- Triggers (Webhook, Schedule, Gmail, Execute Workflow Trigger, ...) are replaced by a Manual Trigger plus your pinned
  data (or one empty item), because the n8n CLI cannot feed them.
- Images are executed by digest. A release candidate may report its base version; use `--allow-same-version` only then
  (it is written into the report).
- **Not tamper-proof** against a deliberately malicious workflow - its code runs in the same container. Run only
  workflows you trust.
- It is evidence for these workflows on these two images, not a guarantee for your production setup.

## Privacy
- Default reports are **shareable**: workflow and node names are replaced by labels (`workflow dr0001`, `node 3`),
  community node types are hidden, error text is shown only for a short list of known-safe messages, and credential data
  never enters the report.
- `--show-names` makes a **private** report with your names - it says so inside the file. Do not share it.
- Nothing is sent anywhere; everything runs on your machine with Docker.

## Requirements
Linux with Docker and the gVisor runtime (`runsc`), Python 3.10+, `sudo` for Docker. Tested with n8n 2.42.3 against the
n8n v3 release-candidate image (2026-10-07).

## Need it done for you?
A written **Tested Upgrade Report** for your instance (your workflows, both versions, the fixes for what changes) is
planned as a paid service - see [localhavenstore.github.io](https://localhavenstore.github.io/self-host-safety/).
Moving an npm/npx n8n to Docker first? The free [n8n Move Check](https://github.com/localhavenstore/n8n-move-check).

MIT licence. Made with AI assistance; reviewed in seven security review rounds before release. Not affiliated with n8n GmbH.
