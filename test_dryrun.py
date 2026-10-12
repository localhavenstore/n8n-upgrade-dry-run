#!/usr/bin/env python3
"""Regression tests for dryrun.py (no containers): rewrite, labels, secrecy, binary, static rules. Fail-closed exit code."""
import re, sys; sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__))); import dryrun as d
F = []
def chk(n, ok): print(("ok   " if ok else "FAIL ") + n); ok or F.append(n)
ok_, bad = {"status": "success"}, {"status": "failed"}
same = [{"error": None, "branches": [[{"json": {"a": 1}}]]}]
# labels
chk("identical records but NEW failed -> FAILED-NEW", d.node_status(ok_, bad, same, same) == "FAILED-NEW")
chk("ERROR-OLD", d.node_status(ok_, ok_, [{"error": "x", "branches": []}], [{"error": None, "branches": [[{"json": {}}]]}]) == "ERROR-OLD")
chk("error without message blocks SAME", d.node_status(ok_, ok_, [{"error": "error (no message)", "branches": [[]]}], [{"error": None, "branches": [[]]}]) == "ERROR-OLD")
chk("partial failure NEW -> FAILED-NEW", d.node_status(ok_, bad, [{"error": None, "branches": []}], None) == "FAILED-NEW")
chk("branch 2 change -> CHANGED", d.node_status(ok_, ok_, [{"error": None, "branches": [[{"json": {"a": 1}}], [{"json": {"b": 1}}]]}],
                                              [{"error": None, "branches": [[{"json": {"a": 1}}], []]}]) == "CHANGED")
chk("loop run 2 change -> CHANGED", d.node_status(ok_, ok_, [{"error": None, "branches": [[]]}, {"error": None, "branches": [[{"json": {"i": 2}}]]}],
                                                [{"error": None, "branches": [[]]}, {"error": None, "branches": [[{"json": {"i": 3}}]]}]) == "CHANGED")
chk("empty runs -> NOT-COMPARED", d.node_status(ok_, ok_, [], []) in ("NOT-COMPARED", "NOT-RUN-BOTH"))
chk("not run on NEW -> NOT-RUN-NEW", d.node_status(ok_, ok_, same, None) == "NOT-RUN-NEW")
# rewrite
wf = {"id": "x; rm -rf /", "nodes": [{"name": "M", "type": "n8n-nodes-base.manualTrigger", "parameters": {}}, {"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}, "credentials": {"a": 1}},
      {"name": "ET", "type": "n8n-nodes-base.executeWorkflowTrigger", "parameters": {}}, {"name": "__dryrun_start", "type": "n8n-nodes-base.set", "parameters": {}}],
      "connections": {}, "pinData": {"Hook": [{"json": {"a": 1}, "binary": {"f": {"data": "aGk=", "mimeType": "text/plain"}}}]}}
w, notes = d.rewrite(wf, "dr0001"); names = [n["name"] for n in w["nodes"]]
chk("own id", w["id"] == "dr0001")
chk("unique start name", len(names) == len(set(names)))
st = [n["name"] for n in w["nodes"] if n["type"] == d.START and n["name"].startswith("__dryrun_start")]
chk("mixed triggers wired (Hook + ET from start)", st and {"Hook", "ET"} <= {c["node"] for c in w["connections"][st[0]]["main"][0]})
chk("pinned binary kept", '"binary"' in [n for n in w["nodes"] if n["name"] == "Hook"][0]["parameters"]["jsCode"])
chk("credentials dropped", "credentials" not in [n for n in w["nodes"] if n["name"] == "Hook"][0])
# secrecy
for t, wv in [("password=abc123", "abc123"), ("Authorization: Bearer xyz.987", "xyz.987"), ("https://u:p4ss@h.io/x", "p4ss"), ("tok A1b2C3d4E5f6G7h8", "A1b2C3d4E5f6G7h8")]:
    chk(f"redact hides {wv!r}", wv not in d.redact(t))
chk("unknown error hidden", d.safe_error("password=x failed") == "error (details hidden - may contain secrets)")
chk("allowlisted phrase has no suffix", d.safe_error("Workflow has issues password abc") == "Workflow has issues")
chk("fake official type hidden", d.safe_error("Unrecognized node type: n8n-nodes-base.mySecret") == "Unrecognized node type (type hidden)")
chk("known removed type shown", d.safe_error("Unrecognized node type: n8n-nodes-base.function") == "Unrecognized node type: n8n-nodes-base.function")
d.SHOW_NAMES = False
chk("community type hidden by default", all("mySecret" not in m for _, _, m in d.static({"nodes": [{"name": "n", "type": "vendor.mySecret"}]})))
chk("static node names redacted", all("abc123" not in nm for nm, _, _ in d.static({"nodes": [{"name": "password=abc123", "type": "n8n-nodes-base.function"}]})))
# binary
chk("opaque binary -> UNVERIFIABLE", d.inline_hash({"data": "filesystem-v2:abc", "id": "x"}) == "UNVERIFIABLE")
chk("bad fileSize format -> UNVERIFIABLE", d.inline_hash({"data": "aGk=", "fileSize": "2 kB"}) == "UNVERIFIABLE")
chk("content hash differs by content", d.inline_hash({"data": "aGk="}) != d.inline_hash({"data": "aG8="}))
# static rules
# 0.9.1: the long-node-id rule (n8n issue 40606) - who gets it, who does not, and what the message may claim
L40, L36 = "long-0a1b2c3d-1111-4222-8333-44445555666", "0a1b2c3d-1111-4222-8333-444455556666"
lid = lambda node: [m for _, l, m in d.static({"nodes": [node]}) if l == "CHECK" and "longer than 36" in m]
chk("0.9.1 long id: a Webhook node with a 40-character id gets exactly one CHECK", len(L40) == 40 and len(lid({"name": "w", "type": "n8n-nodes-base.webhook", "id": L40})) == 1)
chk("0.9.1 long id: 36 characters (a normal id) is NOT flagged, 37 is", len(L36) == 36 and not lid({"name": "w", "type": "n8n-nodes-base.webhook", "id": L36}) and len(lid({"name": "w", "type": "n8n-nodes-base.webhook", "id": L36 + "x"})) == 1)
chk("0.9.1 long id: Wait, Form, a *Trigger node and a send-and-wait operation are flagged too",
    all(len(lid(n)) == 1 for n in ({"name": "a", "type": "n8n-nodes-base.wait", "id": L40}, {"name": "b", "type": "n8n-nodes-base.form", "id": L40}, {"name": "c", "type": "n8n-nodes-base.telegramTrigger", "id": L40},
                                   {"name": "e", "type": "n8n-nodes-base.slack", "id": L40, "parameters": {"operation": "sendAndWait"}})))
chk("0.9.1 long id: a long id on a node that is NOT trigger-like (Set, Code) is not flagged; a missing or non-text id does not crash (control: the same id on a Webhook IS flagged)",
    len(lid({"name": "w", "type": "n8n-nodes-base.webhook", "id": L40})) == 1 and not lid({"name": "s", "type": "n8n-nodes-base.set", "id": L40}) and not lid({"name": "c", "type": "n8n-nodes-base.code", "id": L40}) and not lid({"name": "w", "type": "n8n-nodes-base.webhook"}) and not lid({"name": "w", "type": "n8n-nodes-base.webhook", "id": 12345}))
msg = (lid({"name": "w", "type": "n8n-nodes-base.webhook", "id": L40}) or [""])[0]
chk("0.9.1 long id: the stale-version result is given for BOTH tested versions, with the tested node kind and database, and '2.30+' / 'silently' are gone",
    "did not go live on n8n 2.41.4 and 2.42.7: the first version kept answering." in msg and "Webhook node on Postgres" in msg and "#40606" in msg and "2.30" not in msg and "silently" not in msg)
chk("0.9.1 long id: the deactivation result and 'a new id alone did not free it' are tied to 2.42.7 ONLY (review r11)",
    "On 2.42.7 it also kept answering after the workflow was deactivated, and a new id alone did not free it." in msg and not re.search(r"2\.41\.4[^.]*deactivat", msg))
chk("0.9.1 long id: the fix that worked is named with its version, and re-creating the node is marked as not tested by us",
    "BEFORE the first publish worked (2.42.7)" in msg and "not tested by us" in msg and "database step" in msg)
chk("0.9.1 long id: the id itself never appears in the finding (and there is a finding)", len(msg) > 100 and L40 not in " ".join(str(x) for f in d.static({"nodes": [{"name": "w", "type": "n8n-nodes-base.webhook", "id": L40}]}) for x in f))
chk("Function -> BREAKS", any(l == "BREAKS" for _, l, _ in d.static({"nodes": [{"name": "f", "type": "n8n-nodes-base.function"}]})))
chk("base Code not BREAKS", not any(l == "BREAKS" for _, l, _ in d.static({"nodes": [{"name": "c", "type": "n8n-nodes-base.code"}]})))
chk("Gmail 1.3 BEHAVIOUR, 1.4 not", any(l == "BEHAVIOUR" for _, l, _ in d.static({"nodes": [{"name": "g", "type": "n8n-nodes-base.gmailTrigger", "typeVersion": 1.3}]}))
    and not any(l == "BEHAVIOUR" for _, l, _ in d.static({"nodes": [{"name": "g", "type": "n8n-nodes-base.gmailTrigger", "typeVersion": "1.4"}]})))
chk("If alwaysOutputData only when true", any(l == "BEHAVIOUR" for _, l, _ in d.static({"nodes": [{"name": "i", "type": "n8n-nodes-base.if", "alwaysOutputData": True}]}))
    and not d.static({"nodes": [{"name": "i", "type": "n8n-nodes-base.if", "alwaysOutputData": False}]}))
# every non-comparison status
chk("FAILED-OLD", d.node_status(bad, ok_, None, same) == "FAILED-OLD")
chk("FAILED-BOTH", d.node_status(bad, bad, None, None) == "FAILED-BOTH")
chk("NOT-RUN-BOTH", d.node_status(ok_, ok_, None, None) == "NOT-RUN-BOTH")
chk("RUN-NEW-ONLY", d.node_status(ok_, ok_, None, same) == "RUN-NEW-ONLY")
ub = [{"error": None, "branches": [[d.norm_item({"json": {}, "binary": {"f": {"id": "fs:1"}}})]]}]
chk("UNVERIFIED-BINARY", d.node_status(ok_, ok_, ub, ub) == "UNVERIFIED-BINARY")
chk("ERROR-BOTH", d.node_status(ok_, ok_, [{"error": "x", "branches": []}], [{"error": "y", "branches": []}]) == "ERROR-BOTH")
# privacy marker in the report text
md_private = d.markdown({"old": {"image": "a", "digest": "sha256:" + "0" * 64, "versions": "1"}, "new": {"image": "b", "digest": "sha256:" + "1" * 64, "versions": "2"},
                         "version_check": "ok", "static": {}, "runs": {}, "nodes": [], "rewrites": {}, "note": "n", "names": "shown"})
chk("PRIVATE marker in markdown under --show-names", "PRIVATE REPORT" in md_private)
# 0.9: our own advice text is not redacted (env var names stay readable); node names still are
st9 = d.static({"nodes": [{"name": "token=abcd1234efgh5678ijkl", "type": "n8n-nodes-base.code", "parameters": {}}]})
chk("0.9: advice keeps N8N_RUNNERS_TASK_TIMEOUT readable, node name with a secret is redacted",
    any("N8N_RUNNERS_TASK_TIMEOUT" in m for _, _, m in st9) and all("abcd1234efgh5678ijkl" not in n for n, _, _ in st9))
print("ALL PASSED" if not F else f"{len(F)} failed"); sys.exit(1 if F else 0)
