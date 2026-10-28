#!/usr/bin/env python3
"""Cache pinned public sources, then create a deterministic trajectory sample.

Raw data and full normalized trajectories stay outside git. No source code is run.
"""
import argparse
import concurrent.futures
import csv
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import time
import xml.etree.ElementTree as ET

import pyarrow.parquet as pq
import requests

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "sources.json").read_text())


def csvwrite(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def rank(value):
    return hashlib.sha256((CONFIG["seed"] + str(value)).encode()).hexdigest()


class Collector:
    def __init__(self, raw):
        self.raw = raw
        raw.mkdir(parents=True, exist_ok=True)
        self.manifest = []
        self.failures = []

    def fetch(self, url, rel):
        p = self.raw / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            return p
        for attempt in range(1, 4):
            try:
                usage = shutil.disk_usage(self.raw)
                if usage.used / usage.total >= .85:
                    raise RuntimeError("workspace disk usage exceeds limit")
                size = sum(x.stat().st_size for x in self.raw.rglob("*") if x.is_file())
                if size >= 24_000_000_000:
                    raise RuntimeError("raw cache has reached conservative size limit")
                with requests.get(url, timeout=120, stream=True) as r:
                    r.raise_for_status()
                    with p.with_suffix(p.suffix + ".part").open("wb") as f:
                        for chunk in r.iter_content(1024 * 1024):
                            f.write(chunk)
                p.with_suffix(p.suffix + ".part").rename(p)
                return p
            except Exception as exc:
                self.failures.append(dict(url=url, attempt=attempt, error=str(exc)))
                time.sleep(attempt)
        raise RuntimeError(f"download failed: {url}")

    def hf(self, cfg, name):
        repo, rev = cfg["repo"], cfg["revision"]
        info = json.loads(self.fetch(f"https://huggingface.co/api/datasets/{repo}/revision/{rev}", f"{name}/api.json").read_text())
        self.fetch(f"https://huggingface.co/datasets/{repo}/raw/{rev}/README.md", f"{name}/README.md")
        return info

    def file(self, cfg, name, file):
        return self.fetch(f"https://huggingface.co/datasets/{cfg['repo']}/resolve/{cfg['revision']}/{file}", f"{name}/{file}")

    def add(self, source, cfg, file, path, license, population, selected):
        self.manifest.append(dict(source=source, repository=cfg["repo"], revision=cfg["revision"], file=file,
                                  sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size,
                                  declared_license=license, population_rows=population, sampled_rows=selected))

    def run(self):
        out = []
        cfg = CONFIG["nebius"]
        info = self.hf(cfg, "nebius")
        files = sorted([x["rfilename"] for x in info["siblings"] if x["rfilename"].endswith(".parquet")], key=rank)[:cfg["shards"]]
        by_model = {}
        for file in files:
            p = self.file(cfg, "nebius", file)
            rows = pq.read_table(p, columns=["instance_id", "model_name", "target", "trajectory", "exit_status"]).to_pylist()
            for i, row in enumerate(rows):
                row.update(source="nebius", framework=cfg["framework"], model=row["model_name"],
                           trajectory_id=f"nebius:{file}:{i}", raw_file=f"nebius/{file}", raw_row=i)
                by_model.setdefault(row["model"], []).append(row)
            self.add("nebius", cfg, file, p, info["cardData"]["license"], len(rows), 0)
        for model, rows in sorted(by_model.items()):
            chosen = sorted(rows, key=lambda x: rank(x["trajectory_id"]))[:cfg["per_model"]]
            out.extend(chosen)
        for entry in self.manifest:
            if entry["source"] == "nebius":
                entry["sampled_rows"] = sum(x["raw_file"] == "nebius/" + entry["file"] for x in out)

        cfg = CONFIG["openhands"]
        info = self.hf(cfg, "openhands")
        for file in [x["rfilename"] for x in info["siblings"] if x["rfilename"].endswith(".parquet")]:
            p = self.file(cfg, "openhands", file)
            rows = pq.read_table(p).to_pylist()
            for i, row in enumerate(rows):
                out.append(dict(source="openhands", framework=cfg["framework"], model=cfg["model"],
                                trajectory_id=f"openhands:{i}", instance_id="unavailable", messages=row["messages"],
                                raw_file=f"openhands/{file}", raw_row=i, target=True))
            self.add("openhands", cfg, file, p, info["cardData"]["license"], len(rows), len(rows))

        cfg = CONFIG["mini"]
        for run, model in cfg["runs"].items():
            self.fetch(f"https://raw.githubusercontent.com/{cfg['repo']}/{cfg['revision']}/evaluation/verified/{run}/metadata.yaml", f"mini/{run}/metadata.yaml")
            prefix = f"bash-only/{run}/trajs/"
            listing = self.fetch(f"https://swe-bench-submissions.s3.amazonaws.com/?list-type=2&prefix={prefix}", f"mini/{run}/listing.xml")
            tree = ET.fromstring(listing.read_bytes())
            ns = {"s": "http://s3.amazonaws.com/doc/2006-03-01/"}
            assert tree.findtext("s:IsTruncated", namespaces=ns) == "false", "pagination needed"
            keys = [x.text for x in tree.findall(".//s:Key", ns) if x.text.endswith(".traj.json")]
            chosen = sorted(keys, key=lambda x: rank(x.split("/")[-1]))[:cfg["per_model"]]
            def download(key):
                return key, self.fetch(f"https://swe-bench-submissions.s3.amazonaws.com/{key}", "mini/" + key)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                downloaded = list(pool.map(download, chosen))
            for key, p in downloaded:
                row = json.loads(p.read_text())
                iid = key.split("/")[-2]
                out.append(dict(source="mini", framework=cfg["framework"], model=model,
                                trajectory_id=f"mini:{run}:{iid}", instance_id=iid, messages=row["messages"],
                                raw_file="mini/" + key, raw_row=0, info=row.get("info", {})))
                self.add("mini", cfg, key, p, "not specified by trajectory publisher; scaffold license is not a data license", len(keys), 1)

        cfg = CONFIG["native"]
        info = self.hf(cfg, "native")
        self.file(cfg, "native", "manifest.json")
        self.file(cfg, "native", "schema.json")
        for participant in cfg["participants"]:
            file = f"trajectories/{participant}/run_{cfg['run']}.jsonl.gz"
            p = self.file(cfg, "native", file)
            with gzip.open(p, "rt") as f:
                rows = [json.loads(line) for line in f]
            for i, row in enumerate(rows):
                row.update(source="native", framework={"codex": "Codex", "claude-code": "Claude Code"}[participant],
                           model=row["participant"]["model"], trajectory_id="native:" + row["trajectory_id"],
                           raw_file="native/" + file, raw_row=i)
                out.append(row)
            self.add("native", cfg, file, p, info["cardData"]["license"] + ": third-party terms retained, no relicensing", len(rows), len(rows))

        with gzip.open(self.raw / "sampled_trajectories.jsonl.gz", "wt") as f:
            for row in sorted(out, key=lambda x: x["trajectory_id"]):
                f.write(json.dumps(row) + "\n")
        csvwrite(HERE / "dataset_manifest.csv", self.manifest)
        csvwrite(HERE / "download_failures.csv", self.failures or [dict(url="", attempt=0, error="none")])
        print(f"Sampled {len(out)} trajectories")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, required=True)
    Collector(parser.parse_args().raw).run()
