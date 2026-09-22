#!/usr/bin/env python3
"""Печатает ТЗ по идентификатору из BLOCK*.md:  python task.py T04 [файл]"""
import glob, os, re, sys

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: task.py <ID> [file]")
    tid = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    files = sys.argv[2:] or sorted(glob.glob(os.path.join(here, "BLOCK*.md")))
    for path in files:
        text = open(path, encoding="utf-8").read()
        m = re.search(r'<task id="%s">.*?</task>' % re.escape(tid), text, re.S)
        if m:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            print("Выполни задачу. Правила — AGENTS.md в корне репозитория. Сначала напиши план, затем работай, пока команда из <acceptance> не пройдёт.\n")
            print(m.group(0))
            return
    sys.exit(f"task {tid} not found in {files}")

main()
