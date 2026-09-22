#!/usr/bin/env python3
"""Compare the depproof Scanner's .NET results with .NET's own, project by project.

  compare.py --list list.json --vuln vuln.json --scan <scan output dir> --root <repository root>

.NET's answer: `dotnet list package --include-transitive --format json` (the package set) and
`dotnet list package --vulnerable --include-transitive --format json` (NuGet's audit, GitHub advisory
data). Ours: the scan's SBOM per manifest — the lockfile where a project has one, else the project file.
The repository's own projects are excluded on both sides.

Prints a Markdown report (for the job summary) and exits 1 on any real difference: a package missing
or extra, a vulnerable package we missed or added. A vulnerable package the scan REPORTED AS UNCHECKED
(OSV could not be reached for it) is counted separately and does not fail the run: it is an honest gap,
never a silent one, and the Scanner says so itself.
"""
import argparse
import collections
import json
import os
import sys

ap = argparse.ArgumentParser()
ap.add_argument("--list", required=True)
ap.add_argument("--vuln", required=True)
ap.add_argument("--scan", required=True)
ap.add_argument("--root", required=True)
args = ap.parse_args()
root = os.path.abspath(args.root).replace("\\", "/").rstrip("/") + "/"


def rel(path):
    # Lowercased: a solution may spell a folder differently from the disk (nopCommerce's ChatGPT plugin),
    # and pairing them is the comparison's job, not a Scanner finding.
    p = path.replace("\\", "/")
    return (p[len(root):] if p.startswith(root) else p).lower()


def dotnet_view(path):
    data = json.load(open(path))
    out = {}
    for proj in data.get("projects", []):
        pkgs, vulns = set(), set()
        for fw in proj.get("frameworks", []) or []:
            for key in ("topLevelPackages", "transitivePackages"):
                for p in fw.get(key, []) or []:
                    pid, ver = p["id"].lower(), p.get("resolvedVersion")
                    if not ver:
                        continue
                    pkgs.add((pid, ver))
                    if p.get("vulnerabilities"):
                        vulns.add((pid, ver))
        out[rel(proj["path"])] = (pkgs, vulns)
    return out


def first_party(c):
    return any(pr.get("name") == "depproof:provenance" and pr.get("value") == "first-party"
               for pr in c.get("properties", []))


summary = json.load(open(os.path.join(args.scan, "depproof-summary.json")))
ours = {}
for m in summary["manifests"]:
    if m.get("ecosystem") != "NuGet":
        continue
    sbom = json.load(open(os.path.join(args.scan, os.path.basename(m["sbomFile"]))))
    comps = {(c["name"].lower(), c["version"]) for c in sbom.get("components", [])
             if c.get("purl", "").startswith("pkg:nuget/") and c["version"] != "(local)" and not first_party(c)}
    vulns = set()
    for v in sbom.get("vulnerabilities", []) or []:
        for a in v.get("affects", []):
            name, _, ver = a["ref"].removeprefix("pkg:nuget/").rpartition("@")
            vulns.add((name.lower(), ver))
    # ":Name:1.2.3 (GHSA-…)" — what the scan could not check, and said so.
    unchecked = set()
    for s in m.get("uncheckedSubjects") or []:
        coord = s.split(" (")[0].lstrip(":")
        name, _, ver = coord.rpartition(":")
        unchecked.add((name.lower(), ver))
    ours[m["path"].lower()] = (comps, vulns, unchecked, m.get("fidelity"))


def ours_for(project):
    d = os.path.dirname(project)
    lock = f"{d}/packages.lock.json" if d else "packages.lock.json"
    return (lock, ours[lock]) if lock in ours else (project, ours.get(project))


listing, audit = dotnet_view(args.list), dotnet_view(args.vuln)
t = collections.Counter()
rows = []
for project, (want, _) in sorted(listing.items()):
    src, got = ours_for(project)
    if got is None:
        t["not_scanned"] += 1
        rows.append(f"| `{project}` | not scanned | | |")
        continue
    comps, our_v, unchecked, fidelity = got
    missing, extra = want - comps, comps - want
    want_v = audit.get(project, (set(), set()))[1]
    v_missed = (want_v - our_v) - unchecked
    v_unchecked = (want_v - our_v) & unchecked
    v_added = our_v - want_v
    t["projects"] += 1
    t["packages"] += len(want)
    t["missing"] += len(missing)
    t["extra"] += len(extra)
    t["exact"] += int(not missing and not extra)
    t["vuln"] += len(want_v)
    t["v_missed"] += len(v_missed)
    t["v_unchecked"] += len(v_unchecked)
    t["v_added"] += len(v_added)
    if missing or extra or v_missed or v_added or v_unchecked:
        show = lambda s: ", ".join(f"{n} {v}" for n, v in sorted(s)[:4]) + (" …" if len(s) > 4 else "")
        rows.append(f"| `{project}` | {os.path.basename(src)} ({fidelity}) | "
                    f"missing: {show(missing) or '—'}<br>extra: {show(extra) or '—'} | "
                    f"missed: {show(v_missed) or '—'}<br>unchecked: {show(v_unchecked) or '—'}<br>added: {show(v_added) or '—'} |")

failed = t["missing"] or t["extra"] or t["v_missed"] or t["v_added"] or t["not_scanned"]
print("## depproof vs `dotnet list package`\n")
print(f"**{'❌ Differences' if failed else '✅ Agrees'}** — {t['exact']} of {t['projects']} projects exact, "
      f"{t['packages']} packages; {t['not_scanned']} project(s) not scanned.\n")
print(f"- Packages: missing **{t['missing']}**, extra **{t['extra']}**")
print(f"- Vulnerable packages (NuGet's audit {t['vuln']}): missed **{t['v_missed']}**, added **{t['v_added']}**, "
      f"reported unchecked by the scan {t['v_unchecked']}\n")
if rows:
    print("| Project | Read from | Packages | Vulnerable |\n|---|---|---|---|")
    print("\n".join(rows[:40]))
    if len(rows) > 40:
        print(f"\n…and {len(rows) - 40} more rows in the artifact.")
sys.exit(1 if failed else 0)
