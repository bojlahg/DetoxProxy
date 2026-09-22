#!/usr/bin/env python3
"""Converts external PII benchmarks (downloaded from Hugging Face) into the tests/data jsonl format.

  python tools/convert_holdout.py --src D:/Hackaton/reference/datasets/hf --out tests/data/holdout

Output rows: {"id", "text", "entities": [{"type", "start", "end", "text", "src_type"}], "source", "tags"}
Offsets are char offsets. Types are mapped to the dataset taxonomy used by tools/eval_dataset.py
(FIO, ADDRESS, PHONE, ...). Source types that are not personal data in our sense (public persons,
fictional characters, pets, bare place names, organizations) are dropped from gold, so a mask on them
counts as an extra mask. Source types we do not cover (OGRN, KPP, tokens) keep their original name and
are ignored by the evaluation. Needs pandas + pyarrow.
"""
import argparse, ast, json, os, re, sys
import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HIVETRACE = {"NAME": "FIO", "ADDRESS": "ADDRESS", "PHONE_NUMBER": "PHONE", "EMAIL": "EMAIL", "BANK_CARD_NUMBER": "CARD",
             "CVC": "CVV", "INN": "INN", "PASSPORT_NUMBER": "PASSPORT", "SNILS": "SNILS"}
JAYGUARD = {"PER": "FIO", "PERSON": "FIO", "STREET_ADDRESS": "ADDRESS"}
JAYGUARD_DROP = {"PUBLIC_PER", "PUBLIC_PERSON", "PER_PUBLIC", "FICT", "PET", "GPE", "PUBLIC_PLACES", "THEO"}
ALROSAIT = {"NAME": "FIO", "ADDRESS": "ADDRESS"}


def as_list(v):
    if isinstance(v, str):
        return ast.literal_eval(v)
    return list(v) if v is not None else []


def write(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    spans = sum(len(r["entities"]) for r in rows)
    neg = sum(1 for r in rows if not r["entities"])
    print(f"{path}: {len(rows)} rows, {spans} spans, {neg} without PII")


def hivetrace(src):
    rows = []
    for part in ("domain", "entity"):
        df = pd.read_parquet(os.path.join(src, "hivetrace__pii-bench", "data", f"{part}-00000-of-00001.parquet"))
        for r in df.itertuples():
            ents = []
            for e in as_list(r.entities):
                t = HIVETRACE.get(e["type"], e["type"])
                assert r.text[e["start"]:e["end"]] == e["text"], (r.id, e)
                ents.append({"type": t, "start": int(e["start"]), "end": int(e["end"]), "text": e["text"], "src_type": e["type"]})
            rows.append({"id": f"ht-{r.id}", "text": r.text, "entities": ents, "source": "hivetrace/pii-bench",
                         "tags": [part, r.domain]})
    return rows


def jayguard(src):
    df = pd.read_parquet(os.path.join(src, "just-ai__jayguard-ner-benchmark", "data", "train-00000-of-00001.parquet"))
    rows = []
    for n, r in enumerate(df.itertuples()):
        tokens, tags = list(r.tokens), list(r.ner_tags)
        text, starts = "", []
        for tok in tokens:
            if text:
                text += " "
            starts.append(len(text))
            text += tok
        ents, cur = [], None
        for tok, tag, s in zip(tokens, tags, starts):
            # the source tags every token of a multi-token entity with B-, so consecutive tokens of
            # one type are merged regardless of the B-/I- prefix
            if tag == "O" or (cur and tag[2:] != cur["src_type"]):
                if cur:
                    ents.append(cur)
                cur = None
            if tag != "O":
                if cur is None:
                    cur = {"src_type": tag[2:], "start": s, "end": s + len(tok)}
                else:
                    cur["end"] = s + len(tok)
        if cur:
            ents.append(cur)
        out = []
        for e in ents:
            # trailing punctuation glued to the last token is not part of the entity
            while e["end"] > e["start"] and text[e["end"] - 1] in ".,;:!?)»\"":
                e["end"] -= 1
            if e["src_type"] in JAYGUARD_DROP:
                continue
            t = JAYGUARD.get(e["src_type"], e["src_type"])
            out.append({"type": t, "start": e["start"], "end": e["end"], "text": text[e["start"]:e["end"]], "src_type": e["src_type"]})
        dropped = sorted({e["src_type"] for e in ents if e["src_type"] in JAYGUARD_DROP})
        rows.append({"id": f"jg-{n:04d}", "text": text, "entities": out, "source": "just-ai/jayguard-ner-benchmark",
                     "tags": ["public-or-fictional:" + ",".join(dropped)] if dropped else []})
    return rows


def alrosait(src):
    df = pd.read_json(os.path.join(src, "alrosait__pii-synthetic-ru", "synthetic_pii.jsonl"), lines=True)
    rows, skipped = [], 0
    for r in df.itertuples():
        ents, used, ok = [], [], True
        for e in as_list(r.entities):
            start = -1
            pos = 0
            while True:
                start = r.text.find(e["text"], pos)
                if start < 0 or all(start >= b or start + len(e["text"]) <= a for a, b in used):
                    break
                pos = start + 1
            if start < 0:
                ok = False
                break
            used.append((start, start + len(e["text"])))
            ents.append({"type": ALROSAIT.get(e["type"], e["type"]), "start": start, "end": start + len(e["text"]),
                         "text": e["text"], "src_type": e["type"]})
        if not ok:
            skipped += 1
            continue
        tags = [str(r.domain), str(r.entity_type)]
        if str(r.neg_category) not in ("None", "nan"):
            tags.append("neg:" + str(r.neg_category))
        rows.append({"id": f"al-{r.id}", "text": r.text, "entities": ents, "source": "alrosait/pii-synthetic-ru", "tags": tags})
    print(f"alrosait: skipped {skipped} rows whose entity text is not found verbatim")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=r"D:\Hackaton\reference\datasets\hf")
    ap.add_argument("--out", default="tests/data/holdout")
    a = ap.parse_args()
    write(os.path.join(a.out, "hivetrace_pii_bench.jsonl"), hivetrace(a.src))
    write(os.path.join(a.out, "jayguard_ner.jsonl"), jayguard(a.src))
    write(os.path.join(a.out, "alrosait_synthetic.jsonl"), alrosait(a.src))


if __name__ == "__main__":
    main()
