import json
import sys
from pathlib import Path


def load_specs(root: Path):
    specs = []
    for p in sorted(root.glob("*.json")):
        if p.name.lower() == "openapi.json":
            continue
        with p.open("r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(f"[merge_openapi] skip {p.name}: invalid JSON ({e})", file=sys.stderr)
                continue
        specs.append((p.name, data))
    return specs


def merge_components(dst: dict, src: dict, spec_name: str):
    if not isinstance(src, dict):
        return
    dc = dst.setdefault("components", {})
    sc = src.get("components") or {}
    for section, items in sc.items():
        if not isinstance(items, dict):
            continue
        dsec = dc.setdefault(section, {})
        for name, value in items.items():
            if name in dsec and dsec[name] != value:
                # keep first definition, just warn
                print(f"[merge_openapi] warning: component {section}.{name} from {spec_name} "
                      f"differs from existing, keeping first version", file=sys.stderr)
                continue
            dsec.setdefault(name, value)


def main():
    root = Path(__file__).resolve().parents[1]
    specs = load_specs(root)
    if not specs:
        print("[merge_openapi] no *.json specs found beside openapi.json", file=sys.stderr)
        sys.exit(1)

    # base from first spec
    first_name, first = specs[0]
    merged = {
        "openapi": first.get("openapi", "3.0.0"),
        "info": first.get("info", {"title": "Merged API", "version": "1.0.0"}),
        "paths": {},
    }

    # top-level servers: union of all unique urls
    servers = []
    seen_servers = set()
    for name, spec in specs:
        for srv in spec.get("servers") or []:
            url = (srv or {}).get("url")
            if not url or url in seen_servers:
                continue
            seen_servers.add(url)
            servers.append({"url": url})
    if servers:
        merged["servers"] = servers

    # merge paths, attaching per-path servers from original spec
    for name, spec in specs:
        spec_servers = spec.get("servers") or []
        base_url = spec_servers[0].get("url") if spec_servers else None
        paths = spec.get("paths") or {}
        for path, item in paths.items():
            if path not in merged["paths"]:
                merged_item = json.loads(json.dumps(item))
                # attach path-level servers so адреса не потеряются
                if base_url:
                    existing = merged_item.get("servers") or []
                    urls = {s.get("url") for s in existing if isinstance(s, dict)}
                    if base_url not in urls:
                        existing.append({"url": base_url})
                    if existing:
                        merged_item["servers"] = existing
                merged["paths"][path] = merged_item
            else:
                # simple merge: add missing operations from this spec
                existing = merged["paths"][path]
                for key, value in item.items():
                    if key not in existing:
                        existing[key] = value

        merge_components(merged, spec, name)

    out_path = root / "openapi.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    print(f"[merge_openapi] merged {len(specs)} spec files into {out_path}")


if __name__ == "__main__":
    main()

