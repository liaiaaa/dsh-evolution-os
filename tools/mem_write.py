#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B 级记忆自动入档 —— 只做四件事（2026-10-22 建，依据 plan-v3-codex 修正一）。

1. 路径校验：目标必须落在 knowledge/ 下，拒绝绝对路径与 ../ 逃逸
2. 敏感拦截：内容命中密钥/凭据/身份类模式则拒绝写入
3. 追加留痕：写入 knowledge/_auto/writes-YYYY-MM.md
4. git commit：只提交目标文件与留痕文件

**不**做（按 plan-v3「先手动跑一周」，缓建）：
  SHA 幂等去重、自动追加目标文件变更记录行、逐写体检、细粒度退出码分级。
重复执行会重复追加 —— 这是已知取舍，观察期后再决定是否补 SHA 去重。

用法：
    python3 tools/mem_write.py --target 02-Knowledge/xxx.md \\
        --content-file /tmp/new_section.md --summary "一句话摘要"
    python3 tools/mem_write.py ... --dry-run     # 只校验，不落盘不提交

退出码：
    0 成功       2 路径非法     3 敏感内容命中
    4 目标不存在  5 写入后 git 提交失败（文件已保留，需人工处理）
"""
import argparse
import hashlib
import os
import re
import subprocess
import sys
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOW = os.path.join(BASE, "knowledge")
TRAIL_DIR = os.path.join(KNOW, "_auto")

# 硬拦截模式：命中任一即拒绝写入。宁可误拦，不可漏放 C 级。
SENSITIVE_PATTERNS = [
    ("邮箱等可识别标识", r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
    ("键值型凭据", r"(?i)(api[_ -]?key|access[_ -]?token|password|passwd|secret)\s*[:=]\s*\S+"),
    ("Bearer 凭据", r"(?i)authorization\s*:\s*(?:bearer\s+)?\S+"),
    ("疑似密钥", r"\b(?:sk-|ak_|ghp_|xox[baprs]-)[A-Za-z0-9_\-]{8,}\b"),
    ("证件号码", r"(?i)\b(?:passport|身份证|护照)(?:\s*(?:number|no\.?|号码))?\s*[:：]?\s*[A-Za-z0-9-]{5,}\b"),
    ("私钥块", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]

# 目标目录白名单：只允许写知识库的正式层，不允许写 Inbox / _reports / _auto
ALLOWED_DIRS = ("00-Profile", "01-Projects", "02-Knowledge", "03-Experience", "04-SOP", "05-Skills", "Archive")
DENIED_DIRS = ("Inbox", "_auto", "_reports")


def die(msg, code):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(code)


def resolve_target(target):
    """把 --target 解析为绝对路径，并做越界校验。"""
    if os.path.isabs(target):
        die("--target 必须是 knowledge/ 下的相对路径，不接受绝对路径：%s" % target, 2)
    norm = os.path.normpath(target)
    if norm.startswith("..") or norm.startswith("/"):
        die("--target 存在路径逃逸：%s" % target, 2)
    abs_path = os.path.join(KNOW, norm)
    real_know = os.path.realpath(KNOW)
    real_target = os.path.realpath(abs_path)
    if not (real_target == real_know or real_target.startswith(real_know + os.sep)):
        die("--target 解析后不在 knowledge/ 下：%s" % abs_path, 2)
    head = norm.split(os.sep)[0]
    if head in DENIED_DIRS:
        die("禁止自动写入 %s/（候选缓冲/留痕/报告目录不接受自动入档）" % head, 2)
    if head not in ALLOWED_DIRS:
        die("--target 首层目录不在白名单内：%s（允许：%s）" % (head, ", ".join(ALLOWED_DIRS)), 2)
    return abs_path, norm


def scan_sensitive(text):
    """返回命中的模式名列表（不返回值本身）。"""
    hits = []
    for name, pat in SENSITIVE_PATTERNS:
        if re.search(pat, text):
            hits.append(name)
    return hits


def ensure_trailing_newline(text):
    return text if text.endswith("\n") else text + "\n"


def git(args, cwd):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)


def main():
    ap = argparse.ArgumentParser(description="B 级记忆自动入档（四行为版）")
    ap.add_argument("--target", required=True, help="knowledge/ 下的相对路径，如 02-Knowledge/xxx.md")
    ap.add_argument("--content-file", required=True, help="待追加内容的文件路径")
    ap.add_argument("--summary", required=True, help="一句话摘要，写入留痕与 commit message")
    ap.add_argument("--dry-run", action="store_true", help="只校验，不写文件不提交")
    args = ap.parse_args()

    # ---- 行为 1：路径校验 ----
    abs_target, rel_target = resolve_target(args.target)

    if not os.path.isfile(abs_target):
        die("目标文件不存在：%s（本脚本不自动建新文件；确需新建请先手工创建）" % abs_target, 4)

    if not os.path.isfile(args.content_file):
        die("--content-file 不存在：%s" % args.content_file, 4)

    with open(args.content_file, "r", encoding="utf-8") as f:
        content = f.read()
    if not content.strip():
        die("--content-file 内容为空", 2)
    content = ensure_trailing_newline(content)

    # ---- 行为 2：敏感拦截 ----
    hits = scan_sensitive(content)
    if hits:
        die("内容命中敏感模式，拒绝写入：%s（只报告类型，不报告命中值）" % "、".join(hits), 3)

    summary = args.summary.strip().replace("\n", " ")
    if not summary:
        die("--summary 不能为空", 2)

    if args.dry_run:
        print("[dry-run] 校验通过，未落盘")
        print("  target : %s" % abs_target)
        print("  bytes  : %d" % len(content.encode("utf-8")))
        print("  summary: %s" % summary)
        return 0

    # ---- 行为 3：追加内容 + 留痕 ----
    before = os.path.getsize(abs_target)
    with open(abs_target, "a", encoding="utf-8") as f:
        f.write("\n" + content)
    after = os.path.getsize(abs_target)

    os.makedirs(TRAIL_DIR, exist_ok=True)
    now = datetime.now()
    trail_path = os.path.join(TRAIL_DIR, "writes-%s.md" % now.strftime("%Y-%m"))
    sha12 = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    new_trail = not os.path.isfile(trail_path)
    with open(trail_path, "a", encoding="utf-8") as f:
        if new_trail:
            f.write("# 自动写入留痕 %s\n\n" % now.strftime("%Y-%m"))
            f.write("> 由 `tools/mem_write.py` 自动维护。每行 = 一次 B 级自动入档。\n")
            f.write("> 内容 SHA256 前 12 位可用于比对是否为重复追加。\n\n")
            f.write("| 时间 | 目标 | 摘要 | SHA256-12 |\n|---|---|---|---|\n")
        f.write("| %s | %s | %s | `%s` |\n" % (
            now.strftime("%Y-%m-%d %H:%M:%S"), rel_target, summary.replace("|", "\\|"), sha12))

    # ---- 行为 4：git commit（只提交涉及的两个文件）----
    add = git(["add", "--", abs_target, trail_path], BASE)
    if add.returncode != 0:
        die("git add 失败，文件已写入但未提交：%s" % (add.stderr or add.stdout).strip(), 5)

    msg = "auto: %s %s" % (rel_target, summary)
    commit = git(["commit", "-q", "-m", msg, "--", abs_target, trail_path], BASE)
    if commit.returncode != 0:
        die("git commit 失败，文件已写入但未提交：%s" % (commit.stderr or commit.stdout).strip(), 5)

    head = git(["rev-parse", "--short", "HEAD"], BASE).stdout.strip()

    print("OK")
    print("  target   : %s" % abs_target)
    print("  size     : %d -> %d bytes (+%d)" % (before, after, after - before))
    print("  trail    : %s" % trail_path)
    print("  commit   : %s" % head)
    print("  summary  : %s" % summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
