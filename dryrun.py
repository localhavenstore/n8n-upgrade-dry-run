#!/usr/bin/env python3
"""n8n Upgrade Dry-Run v0.7 (SPEC.md; Codex r1-r6 fixes).
Runs COPIES of exported workflows on an OLD and a NEW n8n image and compares every node's output, plus static checks.
  dryrun.py --workflows export.json --old IMAGE --new IMAGE [--out DIR]
Safety model:
- The user's n8n is never touched: input is an export file. Copies get our own ids (dr0001...); user ids/names never
  reach a shell command.
- One throw-away container per workflow per version: gVisor, no network, all capabilities dropped, no new privileges,
  pid/memory/cpu limits, read-only root with tmpfs for n8n's folders. The ONLY mount is a read-only input directory
  (0700 temp dir, deleted afterwards). The result is read from the container's stdout between random markers - a workflow
  has no shared folder in which to fabricate results.
- Fail-closed: a workflow that does not run cleanly on a side is FAILED on that side; exit code 0 only if every workflow
  ran on both sides and every node gave the SAME output.
- Threat model: this is evidence for YOUR workflows on YOUR machine, not a security attestation of untrusted workflows."""
import argparse, copy, hashlib, html, json, os, re, secrets, subprocess, sys, tempfile

SHOW_NAMES = False      # set by --show-names: PRIVATE report (names/types may contain secrets) - never share it
RULESET = {"version": "2026-10-07b", "source": "https://docs.n8n.io/changelog/v30-breaking-changes/", "checked": "2026-10-07"}
START = "n8n-nodes-base.manualTrigger"
KEEP_START = {"n8n-nodes-base.manualTrigger"}          # every other trigger (incl. Execute Workflow Trigger) gets sample items
NONDETERMINISTIC = {"createdAt", "updatedAt", "executionId"}   # top-level json keys only; disclosed in every report
NET_ERR = re.compile(r"ENOTFOUND|EAI_AGAIN|ECONNREFUSED|getaddrinfo|ENETUNREACH|socket hang up|network", re.I)
HARDEN = ["--runtime=runsc", "-e", "N8N_DEFAULT_BINARY_DATA_MODE=default", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
          "--pids-limit", "512", "--memory", "2g", "--cpus", "2", "--read-only",
          "--tmpfs", "/home/node/.n8n:rw,uid=1000,gid=1000,mode=0700", "--tmpfs", "/tmp:rw,mode=1777"]


SAFE_ERR = re.compile(r"(Unrecognized node type: (?:n8n-nodes-base|@n8n/n8n-nodes-langchain)\.[A-Za-z0-9]{1,60}|Task request timed out|"
                      r"ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ENETUNREACH|getaddrinfo|socket hang up|Workflow did not finish|Workflow has issues|"
                      r"no marked result in the container output|n8n could not import the workflow|no result within \d+ s)")


def safe_error(s):
    """Error text in reports: ONLY allowlisted, known-safe fragments. Anything else is hidden (fail-closed secrecy)."""
    m = SAFE_ERR.findall(str(s or ""))
    def known(x):                                     # only official, known node type names are shown; anything else hidden
        mm = re.fullmatch(r"Unrecognized node type: (?:n8n-nodes-base|@n8n/n8n-nodes-langchain)\.([A-Za-z0-9]+)", x)
        return x if not mm or mm.group(1) in REMOVED | {"executeCommand", "openAi", "code"} else "Unrecognized node type (type hidden)"
    m = [known(x) for x in m]
    return "; ".join(dict.fromkeys(m)) if m else ("error (details hidden - may contain secrets)" if s else None)


def redact(s, n=240):
    s = re.sub(r"(?i)\b(bearer|basic)\s+\S+", r"\1 <redacted>", str(s or ""))
    s = re.sub(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|key|auth|authorization|cookie|session)\b\s*[:=]\s*(?!<redacted>)\S+", r"\1=<redacted>", s)
    s = re.sub(r"://[^/\s:@]+:[^/\s@]+@", "://<userinfo>@", s)
    s = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "<email>", s)
    s = re.sub(r"(https?://[^\s?#]+)\?[^\s]*", r"\1?<query>", s)
    s = re.sub(r"\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{16,}\b", "<token>", s)
    s = re.sub(r"(credential[s]?[^:]{0,20}[:=]\s*)\S+", r"\1<redacted>", s, flags=re.I)
    s = " ".join(s.split())
    return s[:n] + ("..." if len(s) > n else "")


def tv(n):
    try: return float(n.get("typeVersion") or 1)
    except (TypeError, ValueError): return 1.0


def is_trigger(n):
    t = n.get("type", "")
    return t.endswith("Trigger") or t in {"n8n-nodes-base.webhook", "n8n-nodes-base.cron", "n8n-nodes-base.interval", "n8n-nodes-base.start"}


def code_items(items):
    """Pinned/sample items -> Code node source. Keeps json, binary (base64 data) and pairedItem."""
    out = []
    for it in items:
        it = it if isinstance(it, dict) and ("json" in it or "binary" in it) else {"json": it}
        o = {"json": it.get("json", {})}
        if it.get("binary"): o["binary"] = it["binary"]
        if "pairedItem" in it: o["pairedItem"] = it["pairedItem"]
        out.append(o)
    return "return " + json.dumps(out) + ";"


def rewrite(wf, newid):
    """Copy of one workflow, ready for `n8n execute`. Returns (workflow, notes)."""
    w = copy.deepcopy(wf); pins = w.pop("pinData", None) or {}; notes = []
    w["id"] = newid; w["active"] = False
    names = {n["name"] for n in w.get("nodes", [])}
    def uniq(base):
        k, name = 1, base
        while name in names: k += 1; name = f"{base}_{k}"
        names.add(name); return name
    starts = []
    for n in w.get("nodes", []):
        pinned, trig = n["name"] in pins, is_trigger(n)
        if pinned or (trig and n.get("type") not in KEEP_START):
            items = pins.get(n["name"]) or [{"json": {}}]
            n.update(type="n8n-nodes-base.code", typeVersion=2, parameters={"jsCode": code_items(items)})
            n.pop("webhookId", None); n.pop("credentials", None)
            notes.append(f"{n['name']}: " + ("pinned data used" if pinned else "trigger replaced by one empty sample item (no pinned data)"))
            if trig: starts.append(n["name"])
    nodes = w.get("nodes", [])
    has_start = any(n.get("type") in KEEP_START for n in nodes)
    if starts or not has_start:
        targets = {c["node"] for v in w.get("connections", {}).values() for outs in v.get("main", []) for c in (outs or [])}
        roots = sorted(set(starts) | (set() if has_start else {n["name"] for n in nodes if n["name"] not in targets}))
        s = uniq("__dryrun_start")
        nodes.append({"parameters": {}, "name": s, "type": START, "typeVersion": 1, "position": [-240, 0], "id": "dryrun-" + secrets.token_hex(4)})
        w.setdefault("connections", {})[s] = {"main": [[{"node": r, "type": "main", "index": 0} for r in roots]]}
        notes.append(f"start node {s} added in front of: " + ", ".join(roots))
    w["nodes"] = nodes
    return w, [redact(x, 200) for x in notes]


def image_ref(img):
    """Return (ref, digest). A tag is resolved to the digest that is actually used and recorded."""
    pr = subprocess.run(["sudo", "-n", "docker", "pull", "-q", img], capture_output=True, text=True, timeout=900)
    if pr.returncode != 0 and "@sha256:" not in img:
        raise SystemExit(f"pull failed for {img} (a tag must be pulled fresh; give a @sha256 reference to use a local copy)")
    r = subprocess.run(["sudo", "-n", "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", img], capture_output=True, text=True)
    if r.returncode != 0: raise SystemExit(f"image not available: {img}")
    ds = json.loads(r.stdout.strip() or "[]")
    full = next((d for d in ds if "@" in d), None)                     # exact repo@sha256 Docker resolved -> what we execute
    if not full: raise SystemExit(f"image has no registry digest: {img}")
    return full, full.split("@", 1)[1]


def inline_hash(v):
    """Content hash only for proven inline data (valid base64, no storage id, size matches when given)."""
    import base64
    d = v.get("data")
    if v.get("id") or not isinstance(d, str): return "UNVERIFIABLE"
    try: raw = base64.b64decode(d, validate=True)
    except Exception: return "UNVERIFIABLE"
    fs = str(v.get("fileSize") or "").strip()
    if fs:
        m = re.fullmatch(r"(\d+)\s*B", fs)
        if not m or int(m.group(1)) != len(raw): return "UNVERIFIABLE"
    return hashlib.sha256(raw).hexdigest()[:16]


def norm_item(i):
    j = {k: v for k, v in (i.get("json") or {}).items() if k not in NONDETERMINISTIC}
    b = {k: {"mimeType": v.get("mimeType"), "fileName": v.get("fileName"), "fileSize": v.get("fileSize"),
             "sha256": inline_hash(v)}
         for k, v in (i.get("binary") or {}).items()}
    return {"json": j, "binary": b} if b else {"json": j}


def run_one(image, wf, timeout=300):
    """One workflow, one version, one throw-away container. Result read from stdout between random markers."""
    tag = secrets.token_hex(16)
    if not re.fullmatch(r"dr\d{4}", wf["id"]): raise ValueError("internal id expected")
    with tempfile.TemporaryDirectory(prefix="dryrun-") as d:
        os.chmod(d, 0o700)
        p = os.path.join(d, "wf.json"); json.dump([wf], open(p, "w")); os.chmod(p, 0o600)
        script = ("n8n --version 2>/dev/null | tail -1 | sed 's/^/VER:/'; n8n import:workflow --input=/in/wf.json >/dev/null 2>&1 || "
                  "{ echo IMPORT-FAILED; exit 3; }; echo BEGIN-" + tag + "; n8n execute --id " + wf["id"] + " --rawOutput 2>&1; "
                  "rc=$?; echo; echo END-" + tag + " $rc")
        try:
            r = subprocess.run(["sudo", "-n", "docker", "run", "--rm", "--name", "dryrun-" + tag, *HARDEN, "-e", "N8N_DIAGNOSTICS_ENABLED=false",
                                "-e", "N8N_ENCRYPTION_KEY=" + secrets.token_hex(16), "-v", f"{d}:/in:ro", "--entrypoint", "sh", image, "-c", script],
                               capture_output=True, text=True, timeout=timeout)
            out = r.stdout
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo", "-n", "docker", "rm", "-f", "dryrun-" + tag], capture_output=True, timeout=60)
            return {"status": "timeout", "error": f"no result within {timeout} s", "nodes": {}, "version": "?"}
    ver = (re.search(r"^VER:(\S+)", out, re.M) or [None, "?"])[1]
    if "IMPORT-FAILED" in out: return {"status": "import-failed", "error": "n8n could not import the workflow", "nodes": {}, "version": ver}
    m = re.search(r"BEGIN-" + tag + r"\n(.*)\nEND-" + tag + r" (\d+)", out, re.S)
    if not m: return {"status": "no-result", "error": "no marked result in the container output", "nodes": {}, "version": ver}
    body, rc = m.group(1), int(m.group(2))
    j = body.find("{"); data = None
    if j >= 0:
        try: data = json.loads(body[j:body.rfind("}") + 1])
        except ValueError: data = None
    if not data:
        e = re.search(r"((?:[A-Z]\w*)?Error|Problem[^:]{0,40}|Unrecognized node type[^:]{0,80})[:\s]+(.{0,200}?)(?=\s+at\s|$)", " ".join(body.split()))
        return {"status": "failed", "error": safe_error(body), "nodes": {}, "version": ver, "rc": rc}
    rd = data.get("data", {}).get("resultData", {})
    nodes = {}
    for name, nruns in rd.get("runData", {}).items():
        nodes[name] = [{"error": (safe_error((r.get("error") or {}).get("message")) or "error (no message)") if r.get("error") else None,
                        "branches": [[norm_item(i) for i in (br or [])] for br in ((r.get("data") or {}).get("main") or [])]} for r in nruns]
    st = data.get("status") or ("success" if data.get("finished") else "failed")
    if rc != 0 and st == "success": st = f"failed (n8n exit code {rc})"
    return {"status": st, "error": safe_error((rd.get("error") or {}).get("message")) if rd.get("error") else None, "nodes": nodes,
            "version": ver, "rc": rc}


def node_status(a, b, na, nb):
    """a/b = workflow results OLD/NEW; na/nb = list of runs of one node (or None)."""
    ok_a, ok_b = a["status"] == "success", b["status"] == "success"
    ea = bool(na) and any(r["error"] for r in na); eb = bool(nb) and any(r["error"] for r in nb)
    if na is None and nb is None:
        if ok_a and ok_b: return "NOT-RUN-BOTH"
        return "FAILED-BOTH" if not ok_a and not ok_b else ("FAILED-NEW" if not ok_b else "FAILED-OLD")
    if nb is None: return "FAILED-NEW" if not ok_b else "NOT-RUN-NEW"
    if na is None: return "FAILED-OLD" if not ok_a else "RUN-NEW-ONLY"
    if ea and eb: return "ERROR-BOTH"
    if eb: return "ERROR-NEW"
    if ea: return "ERROR-OLD"
    if not (ok_a and ok_b): return "FAILED-BOTH" if not ok_a and not ok_b else ("FAILED-NEW" if not ok_b else "FAILED-OLD")
    if not na or not nb: return "NOT-COMPARED"
    if "UNVERIFIABLE" in json.dumps([na, nb]): return "UNVERIFIED-BINARY"
    return "SAME" if [r["branches"] for r in na] == [r["branches"] for r in nb] else "CHANGED"


def exercise(n_runs):
    if not n_runs: return "not reached"
    e = " ".join(str(r["error"] or "") for r in n_runs)
    if NET_ERR.search(e): return "blocked (no network)"
    return "failed" if e.strip() else "exercised"


REMOVED = {"function", "functionItem", "itemLists", "cron", "interval", "htmlExtract", "iCal", "moveBinaryData", "readBinaryFile",
           "readBinaryFiles", "writeBinaryFile", "readPDF", "workflowTrigger", "orbit", "openAiAssistant", "lmOpenAi", "toolHttpRequest",
           "toolSerpApi", "manualChatTrigger", "memoryChatRetriever", "memoryMotorhead", "memoryZep", "documentBinaryInputLoader",
           "documentJsonInputLoader", "documentGithubLoader", "vectorStoreInMemoryInsert", "vectorStoreInMemoryLoad",
           "vectorStorePineconeInsert", "vectorStorePineconeLoad", "vectorStoreSupabaseInsert", "vectorStoreSupabaseLoad",
           "vectorStoreZep", "vectorStoreZepInsert", "vectorStoreZepLoad", "aiTransform"}
OLDMODES = {"conversationalAgent", "openAiFunctionsAgent", "planAndExecuteAgent", "reActAgent", "sqlAgent"}


def static(wf):
    return [(redact(nm, 100), lvl, redact(msg, 200)) for nm, lvl, msg in _static(wf)]


def _static(wf):
    out = []
    for n in wf.get("nodes", []):
        t = n.get("type", ""); short = t.split(".")[-1]; v = tv(n); p = n.get("parameters") or {}
        base, lc = t.startswith("n8n-nodes-base."), t.startswith("@n8n/n8n-nodes-langchain.")
        if (base or lc) and short in REMOVED: out.append((n["name"], "BREAKS", f"node type {short} is on the removed list"))
        if base and short == "openAi": out.append((n["name"], "BREAKS", "OpenAI (legacy version) is removed"))
        if lc and short == "code": out.append((n["name"], "BREAKS", "LangChain Code (legacy) is removed"))
        if t == "@n8n/n8n-nodes-langchain.agent" and v < 2 and (p.get("agent") in OLDMODES or (p.get("agent") is None and v <= 1.5)):
            out.append((n["name"], "BREAKS", "AI Agent v1 in an old agent mode is removed"))
        if t in ("n8n-nodes-base.if", "n8n-nodes-base.switch") and n.get("alwaysOutputData") is True:
            out.append((n["name"], "BEHAVIOUR", "Always Output Data: an empty item only when EVERY output is empty"))
        if t == "n8n-nodes-base.gmailTrigger" and v < 1.4:
            out.append((n["name"], "BEHAVIOUR", "Gmail Trigger below 1.4 runs as 1.4 (mails per poll, drafts and sent mails)"))
        if t == "n8n-nodes-base.executeWorkflow" and p.get("source") in ("localFile", "url"):
            out.append((n["name"], "CHECK", "sub-workflow from a local file / URL"))
        js = json.dumps(p)
        if "$getPairedItem" in js or "$evaluateExpression" in js: out.append((n["name"], "CHECK", "uses $getPairedItem / $evaluateExpression"))
        if t == "n8n-nodes-base.executeCommand": out.append((n["name"], "CHECK", "Execute Command: the command must exist in the 3.0 image (Alpine, no apk)"))
        if t == "n8n-nodes-base.code": out.append((n["name"], "INFO", "Code steps longer than 60 s fail in 3.0 unless N8N_RUNNERS_TASK_TIMEOUT is raised"))
        nid = n.get("id")
        trig = short.lower().endswith("trigger") or t.split(".")[-1] in ("webhook", "wait", "form") or p.get("operation") == "sendAndWait"
        if isinstance(nid, str) and len(nid) > 36 and trig:
            out.append((n["name"], "CHECK", "trigger-like node id is longer than 36 characters: on Postgres with n8n 2.30+ publishing can silently keep "
                                          "serving the OLD version (n8n issue #40606) - re-create this node (copy/paste) so it gets a normal id"))
        if "." in t and not base and not lc:
            out.append((n["name"], "CHECK", "community node (" + (redact(t, 80) if SHOW_NAMES else "type hidden") + "): unverified community packages are off by default in 3.0"))
    return out


def esc(s): return html.escape(str(s)).replace("|", "\\|").replace("\n", " ")


def markdown(rep):
    L = ["# n8n Upgrade Dry-Run report", "",
         f"- old: `{esc(rep['old']['image'])}` digest `{rep['old']['digest'][:19]}...` (reports {esc(rep['old']['versions'])})",
         f"- new: `{esc(rep['new']['image'])}` digest `{rep['new']['digest'][:19]}...` (reports {esc(rep['new']['versions'])})",
         f"- static rule set {RULESET['version']} from {RULESET['source']} (checked {RULESET['checked']})",
         f"- version check: {esc(rep['version_check'])}",
         ("- **PRIVATE REPORT (--show-names): names and types are shown and may contain secrets - do not share this file.**"
          if rep.get("names") == "shown" else "- names: hidden (opaque labels) - this report is meant to be shareable"), "",
         "## Static findings", ""]
    rows = [(w, f) for w, fs in rep["static"].items() for f in fs]
    L += [f"- **{lvl}** {esc(w)} / {esc(node)}: {esc(msg)}" for w, (node, lvl, msg) in rows] or ["- none"]
    L += ["", "## Runs per workflow", "", "| workflow | old | new |", "|---|---|---|"]
    for w, r in rep["runs"].items():
        f = lambda x: esc(x["status"] + (f" - {x['error']}" if x.get("error") else ""))
        L.append(f"| {esc(w)} | {f(r['old'])} | {f(r['new'])} |")
    L += ["", "## Every node", "", "| workflow | node | result | on old | on new |", "|---|---|---|---|---|"]
    L += [f"| {esc(r['workflow'])} | {esc(r['node'])} | {r['status']} | {r['old_exercise']} | {r['new_exercise']} |" for r in rep["nodes"]]
    same = sum(1 for r in rep["nodes"] if r["status"] == "SAME")
    L += ["", f"{same} of {len(rep['nodes'])} nodes gave the SAME output (all runs, all output branches, json + binary metadata).",
          f"Ignored as non-deterministic: top-level json keys {sorted(NONDETERMINISTIC)}.", "", "## Rewrites used for the test run", ""]
    L += [f"- {esc(w)}: {esc(n)}" for w, ns in rep["rewrites"].items() for n in ns]
    L += ["", rep["note"]]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--workflows", required=True); ap.add_argument("--old", required=True)
    ap.add_argument("--new", required=True); ap.add_argument("--out", default="dryrun-report")
    ap.add_argument("--allow-same-version", action="store_true", help="for release candidates that report the old base version")
    ap.add_argument("--show-names", action="store_true", help="PRIVATE report: show workflow/node names and community node types (may contain secrets - do NOT share)")
    a = ap.parse_args()
    global SHOW_NAMES; SHOW_NAMES = a.show_names
    src = json.load(open(a.workflows)); src = src if isinstance(src, list) else [src]
    if not src: raise SystemExit("no workflows in the export")
    (oimg, odig), (nimg, ndig) = image_ref(a.old), image_ref(a.new)
    if odig == ndig: raise SystemExit("old and new image are the same image (same digest)")
    ids = [f"dr{i + 1:04d}" for i in range(len(src))]
    pairs = [rewrite(w, i) for w, i in zip(src, ids)]
    runs, rows, vo, vn = {}, [], set(), set()
    label = {}
    def wn(o, w):                                                   # opaque unless --show-names
        return redact(o.get("name") or w["id"], 100) + f" [{w['id']}]" if a.show_names else f"workflow {w['id']}"
    def nn(w, n):
        if a.show_names: return redact(n, 100)
        k = (w["id"], n); label.setdefault(k, f"node {sum(1 for x in label if x[0] == w['id']) + 1}"); return label[k]
    for (wf, notes), orig in zip(pairs, src):
        name = wn(orig, wf)
        ra, rb = run_one(oimg, wf), run_one(nimg, wf)
        vo.add(ra["version"]); vn.add(rb["version"])
        runs[name] = {"old": {k: ra.get(k) for k in ("status", "error")}, "new": {k: rb.get(k) for k in ("status", "error")}}
        node_names = [n["name"] for n in wf.get("nodes", [])]
        if not node_names: rows.append({"workflow": name, "node": "(none)", "status": "EMPTY", "old_exercise": "-", "new_exercise": "-"})
        for n in node_names:
            na, nb = ra["nodes"].get(n), rb["nodes"].get(n)
            rows.append({"workflow": name, "node": nn(wf, n), "status": node_status(ra, rb, na, nb),
                         "old_exercise": exercise(na), "new_exercise": exercise(nb)})
    def vk(v):
        try: return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
        except ValueError: return ()
    vwarn = None
    if len(vo) != 1 or len(vn) != 1 or "?" in vo | vn: vwarn = "a container did not report a clear version"
    elif vk(next(iter(vn))) <= vk(next(iter(vo))): vwarn = f"NEW reports {next(iter(vn))}, not newer than OLD {next(iter(vo))}"
    if vwarn and not a.allow_same_version:
        raise SystemExit(f"version check failed: {vwarn} (use --allow-same-version only for release candidates, it is recorded)")
    rep = {"version_check": vwarn or "ok", "old": {"image": oimg, "digest": odig, "versions": ", ".join(sorted(vo))},
           "new": {"image": nimg, "digest": ndig, "versions": ", ".join(sorted(vn))}, "ruleset": RULESET,
           "rewrites": {wn(o, w): (n if a.show_names else [f"{len(n)} rewrite(s) - names hidden"] if n else []) for (w, n), o in zip(pairs, src)},
           "static": {wn(o, w): [((nm if a.show_names else nn(w, raw)), lvl, msg) for (nm, lvl, msg), raw in zip(static(o), [x[0] for x in _static(o)])]
                      for (w, _), o in zip(pairs, src)}, "runs": runs, "nodes": rows, "names": "shown" if a.show_names else "hidden (opaque labels)",
           "privacy": "PRIVATE - names and types may contain secrets - do not share" if a.show_names else "shareable (opaque labels, no names)",
           "note": "One test run per workflow on throw-away containers without network - evidence for these workflows on these images, "
                   "not a guarantee. Nodes that need the network show 'blocked (no network)'. Not tamper-proof against a deliberately malicious "
                   "workflow (its code runs in the same container) - run only workflows you trust; triggers get sample items via a Manual "
                   "Trigger + Code node (the CLI cannot feed an Execute Workflow Trigger)."}
    os.makedirs(a.out, exist_ok=True)
    json.dump(rep, open(os.path.join(a.out, "report.json"), "w"), indent=1)
    open(os.path.join(a.out, "report.md"), "w").write(markdown(rep))
    cnt = {}
    for r in rows: cnt[r["status"]] = cnt.get(r["status"], 0) + 1
    print(json.dumps({"summary": cnt, "old": rep["old"]["versions"], "new": rep["new"]["versions"], "report": os.path.join(a.out, "report.md")}))
    ok = bool(rows) and all(r["status"] == "SAME" for r in rows) and all(x["old"]["status"] == "success" and x["new"]["status"] == "success" for x in runs.values())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
