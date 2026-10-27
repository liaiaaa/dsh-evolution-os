#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""重建 knowledge/INDEX.md —— 全库文件清单 + 一句话摘要 + mtime。

用途（plan-v3-codex 修正三）：grep 召回依赖 Agent 自己猜关键词，猜错就静默漏检。
INDEX 是「库里有什么」的清单，不依赖猜——Agent 任务开头先读它，命中再打开具体文件。

用法：
    python3 tools/build_index.py            # 重建 INDEX.md
    python3 tools/build_index.py --check    # 只检查是否过期（不写），退出码 1 表示过期

扫描范围：knowledge/ 下所有 .md，排除
    - INDEX.md 自身
    - Inbox/（候选缓冲，天然未批准）
    - _auto/（写入留痕）
    - _reports/（体检报告与历史产物）
"""
import argparse
import os
import re
import sys
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOW = os.path.join(BASE, "knowledge")
INDEX_PATH = os.path.join(KNOW, "INDEX.md")
EXCLUDE_DIRS = ("Inbox", "_auto", "_reports", ".obsidian", ".trash", "Archive")
# 这些行不足以概括文件主旨：标题、引用、表格、分隔线、代码块、列表项、迁入记录
SKIP_PREFIXES = ("#", ">", "|", "---", "```", "<!--", "*迁入记录", "- ", "* ", "+ ")
ORDERED_ITEM = re.compile(r"^\d+[.)]\s")
# 整行斜体（`*来源：…*`、`*迁入记录：…*`）是元信息，不是内容主旨
META_LINE = re.compile(r"^\*[^*].*\*$")
SUMMARY_MAX = 55


def pick_summary(path):
    """从 markdown 里挑一句摘要：优先第一段自然段，退化到 H1 标题。

    跳过列表项（`- ` / `1. `）——列表第一项通常不是文件主旨，实测会给出误导性摘要
    （如「- 等级为 low/medium/high…」）。
    """
    title = None
    natural = None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return "(不可读)"

    for raw in lines[:60]:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("# "):
            if title is None:
                title = line[2:].strip()
            continue
        if line.startswith(SKIP_PREFIXES) or ORDERED_ITEM.match(line) or META_LINE.match(line):
            continue
        if len(line) < 10:
            continue
        natural = line
        break

    if natural:
        return clip(natural)
    return clip(title) if title else "(无摘要)"


def clip(text):
    text = " ".join(text.split())
    if len(text) <= SUMMARY_MAX:
        return text
    cut = text[:SUMMARY_MAX]
    # 尽量避免截断在句子中间：优先在标点处收尾
    for sep in ("。", "；", "，", ";", ","):
        i = cut.rfind(sep)
        if i > SUMMARY_MAX * 0.55:
            return cut[:i] + "…"
    return cut[:SUMMARY_MAX - 1] + "…"


def collect():
    entries = []
    for root, dirs, files in os.walk(KNOW):
        rel_root = os.path.relpath(root, KNOW)
        top = rel_root.split(os.sep)[0] if rel_root != "." else ""
        if top in EXCLUDE_DIRS:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in sorted(files):
            if not name.endswith(".md"):
                continue
            abs_path = os.path.join(root, name)
            if os.path.abspath(abs_path) == os.path.abspath(INDEX_PATH):
                continue
            rel = os.path.relpath(abs_path, KNOW)
            mtime = datetime.fromtimestamp(os.path.getmtime(abs_path)).strftime("%Y-%m-%d")
            entries.append((rel.replace(os.sep, "/"), pick_summary(abs_path), mtime))
    entries.sort(key=lambda e: e[0])
    return entries


def render(entries):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [
        "# 知识库索引",
        "",
        "> **自动生成，请勿手改。** 重建：`python3 tools/build_index.py`",
        ">",
        "> 用途：Agent 任务开头先读本表，判断「库里有没有相关结论」，命中再打开具体文件。",
        "> 本表只列正式目录；`Inbox/`（候选缓冲）、`_auto/`（写入留痕）、`_reports/`（体检报告）不在此列。",
        "",
        "- 生成时间：%s" % now,
        "- 条目数：**%d**" % len(entries),
        "",
        "| 文件 | 摘要 | 更新 |",
        "|---|---|---|",
    ]
    for rel, summary, mtime in entries:
        out.append("| `%s` | %s | %s |" % (rel, summary.replace("|", "\\|"), mtime))
    out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="重建 knowledge/INDEX.md")
    ap.add_argument("--check", action="store_true", help="只检查是否过期，不写文件")
    args = ap.parse_args()

    if not os.path.isdir(KNOW):
        print("ERROR: knowledge 目录不存在：%s" % KNOW, file=sys.stderr)
        return 2

    entries = collect()
    new_text = render(entries)

    if args.check:
        if not os.path.isfile(INDEX_PATH):
            print("INDEX.md 不存在（过期）")
            return 1
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            old = f.read()
        # 只比对表体，忽略生成时间行
        old_body = "\n".join(l for l in old.splitlines() if not l.startswith("- 生成时间："))
        new_body = "\n".join(l for l in new_text.splitlines() if not l.startswith("- 生成时间："))
        if old_body != new_body:
            print("INDEX.md 已过期，需重建")
            return 1
        print("INDEX.md 是最新的（%d 条）" % len(entries))
        return 0

    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        f.write(new_text)
    print("已重建 INDEX.md：%d 条 -> %s" % (len(entries), INDEX_PATH))
    print("  体积：%d 字节" % os.path.getsize(INDEX_PATH))
    return 0


if __name__ == "__main__":
    sys.exit(main())
