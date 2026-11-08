#!/usr/bin/env python3
"""
Clash classical rule-provider (payload: - TYPE,VALUE[,no-resolve]) -> sing-box rule-set source JSON.

Supported:  DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX, IP-CIDR, IP-CIDR6, IP-ASN, PROCESS-NAME, PROCESS-PATH
IP-ASN is expanded to announced prefixes via RIPEstat at build time (sing-box has no ASN matcher).
Anything else is reported on stderr and skipped (non-zero exit only with --strict).

usage: clash2sing.py <in.yaml> <out.json> [--strict] [--no-asn]
"""
import ipaddress
import json
import sys
import urllib.request

import yaml

RIPE = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}"


def asn_prefixes(asn: str) -> list[str]:
    with urllib.request.urlopen(RIPE.format(asn), timeout=30) as r:
        data = json.load(r)
    return [p["prefix"] for p in data["data"]["prefixes"]]


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    strict = "--strict" in sys.argv
    no_asn = "--no-asn" in sys.argv
    src, dst = args

    payload = yaml.safe_load(open(src, encoding="utf-8")).get("payload") or []
    domain_fields = {"domain": set(), "domain_suffix": set(), "domain_keyword": set(), "domain_regex": set()}
    cidrs: set[str] = set()
    procs = {"process_name": set(), "process_path": set()}
    skipped: list[str] = []

    for raw in payload:
        parts = [p.strip() for p in str(raw).split(",")]
        if len(parts) < 2 or not parts[1]:
            skipped.append(str(raw))
            continue
        t, v = parts[0].upper(), parts[1]
        if t == "DOMAIN":
            domain_fields["domain"].add(v.lower())
        elif t == "DOMAIN-SUFFIX":
            domain_fields["domain_suffix"].add(v.lower().lstrip("."))
        elif t == "DOMAIN-KEYWORD":
            domain_fields["domain_keyword"].add(v.lower())
        elif t == "DOMAIN-REGEX":
            domain_fields["domain_regex"].add(v)
        elif t in ("IP-CIDR", "IP-CIDR6"):
            # strict=False: normalize host bits, e.g. 38.92.213.211/24 -> 38.92.213.0/24
            cidrs.add(str(ipaddress.ip_network(v, strict=False)))
        elif t == "PROCESS-NAME":
            procs["process_name"].add(v)
        elif t == "PROCESS-PATH":
            procs["process_path"].add(v)
        elif t == "IP-ASN":
            if no_asn:
                skipped.append(f"{raw} (asn expansion disabled)")
                continue
            pfx = asn_prefixes(v)
            print(f"[asn] AS{v}: {len(pfx)} prefixes", file=sys.stderr)
            cidrs.update(str(ipaddress.ip_network(p, strict=False)) for p in pfx)
        else:
            skipped.append(str(raw))

    # Collapse overlapping CIDRs per family
    v4 = ipaddress.collapse_addresses(ipaddress.ip_network(c) for c in cidrs if ":" not in c)
    v6 = ipaddress.collapse_addresses(ipaddress.ip_network(c) for c in cidrs if ":" in c)
    ip_cidr = [str(n) for n in v4] + [str(n) for n in v6]

    # Two separate headless rules: rules inside a rule-set are OR-ed, so domain vs IP
    # matching semantics don't depend on intra-rule field grouping.
    rules = []
    dom_rule = {k: sorted(v) for k, v in domain_fields.items() if v}
    if dom_rule:
        rules.append(dom_rule)
    if ip_cidr:
        rules.append({"ip_cidr": ip_cidr})
    proc_rule = {k: sorted(v) for k, v in procs.items() if v}
    if proc_rule:
        rules.append(proc_rule)

    with open(dst, "w", encoding="utf-8") as f:
        json.dump({"version": 2, "rules": rules}, f, ensure_ascii=False, indent=2)

    stats = {k: len(v) for k, v in dom_rule.items()} | {"ip_cidr": len(ip_cidr)} | {k: len(v) for k, v in proc_rule.items()}
    print(f"[ok] {src} -> {dst} {stats}", file=sys.stderr)
    for s in skipped:
        print(f"[skip] {s}", file=sys.stderr)
    return 1 if (strict and skipped) else 0


if __name__ == "__main__":
    sys.exit(main())
