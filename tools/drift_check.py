# -*- coding: utf-8 -*-
"""漂移检测器：只读审计 mem0 history、权威源、Inbox 与治理规则。"""
import json
import os
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

BASE = os.environ.get("DSH_BASE") or str(Path(__file__).resolve().parent.parent)
KNOW = os.path.join(BASE, "knowledge")
DB = os.environ.get("DSH_MEM0_DB") or str(Path(BASE) / "mem0.db")
PROFILE = os.path.join(KNOW, "00-Profile", "个人偏好.md")
PROTOCOL = os.path.join(KNOW, "00-Profile", "个人AI协议.md")
INBOX = os.path.join(KNOW, "Inbox")
REPORT_DIR = os.path.join(INBOX, "_reports")

RULES = [
    ("身份泄漏", [
        r"John Doe", r"张三", r"\bname is\b", r"undergraduate student",
        r"Example University", r"示例大学", r"\b22[- ]year[- ]old\b",
        r"示例城市", r"Example City", r"示例笔记本品牌", r"示例手机型号",
        r"示例CPU", r"示例GPU", r"示例内存规格",
    ]),
    ("获奖记录", [
        r"\bwon\b", r"\bprize\b", r"medal", r"championship", r"一等奖",
        r"二等奖", r"冠军", r"银牌", r"Blue Bridge", r"蓝桥杯",
        r"World Robot", r"世界机器人", r"技能大赛",
    ]),
    ("项目状态", [
        r"iCAN", r"挑战杯", r"registration deadline", r"报名截止",
        r"\bcompetitions?\b", r"竞赛", r"赛道", r"\btrack\b",
        r"\bsubmits?\b", r"\bsubmitted\b", r"提交", r"参赛",
        r"项目进度", r"项目状态", r"当前项目", r"\bproject status\b",
    ]),
    ("个人生活", [
        r"Valorant", r"无畏契约", r"闲鱼", r"电源计划", r"power plan",
        r"WeChat", r"\b微信\b", r"QQ Browser", r"QQ浏览器", r"\bWPS\b",
        r"Screen Recorder", r"\b录屏\b",
        r"anime next-gen", r"AI multimedia", r"AI 多媒体", r"国漫",
    ]),
    ("时效性", [
        r"20\d\d[-年]\d", r"deadline", r"截止", r"until \d", r"截至",
        r"version \d", r"版本 \d", r"currently learning", r"正在学习",
        r"approximately \d+ days", r"in \d+ days",
    ]),
    ("绝对化", [
        r"绝不", r"一律", r"必须", r"总是", r"永远", r"严禁", r"不得",
        r"\balways\b", r"\bnever\b", r"\bmust\b", r"\bmandates?\b",
        r"explicitly refuses", r"cannot", r"禁止",
    ]),
    ("凭据/密钥", [
        r"api[_ ]?key", r"token", r"password", r"secret", r"密钥",
        r"sk-[A-Za-z0-9]{8,}", r"ak_[A-Za-z0-9]{8,}",
    ]),
]

ABSOLUTE_EXEMPT = [
    "mandates human-in-the-loop", "requires explicit consent",
    "must be approved first", "must proactively inquire",
    "must never silently skip", "explicitly rejected docker",
    "does not delegate final approval", "must ask whether to precipitate",
    "must inquire at task closure",
]

# 仅作“疑似已确认偏好”的保守提示；未命中者不得自动归为 A 级。
KEEP_HINTS = [
    "conclusion-first", "Simplified Chinese", "structured, format-preserving",
    "faithful adherence", "specific, practically grounded",
    "clarifying questions", "phased execution", "human-in-the-loop",
    "PowerShell", "manual, on-demand", "lightweight architecture",
    "read-only operations", "cost-performance ratio",
    "software binaries", "ask for confirmation before depositing",
    "development toolchains", "task closure", "ask the user whether",
    "precipitate", "quality-critical", "explicit consent before any system configuration",
    "prefers E drive", "drive E:",
    "ask whether to precipitate", "should ask whether",
]

SENSITIVE_TYPES = ("凭据/密钥", "身份泄漏")

# 分类检测与报告脱敏共用同一组敏感模式，避免“报告知道敏感、分类器不知道敏感”。
SENSITIVE_PATTERNS = [
    ("邮箱等可识别标识", r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[邮箱已脱敏]"),
    ("证件号码", r"(?i)\b(?:passport|身份证|护照)(?:\s*(?:number|no\.?|号码))?\s*[:：]?\s*[A-Za-z0-9-]{5,}\b", "[证件信息已脱敏]"),
    ("Bearer 凭据", r"(?i)\bauthorization\s*:\s*(?:bearer\s+)?\S+", "Authorization: [已脱敏]"),
    ("键值型凭据", r"(?i)(api[_ -]?key|token|password|secret)\s*[:=]\s*\S+", r"\1=[已脱敏]"),
    ("疑似密钥", r"\b(?:sk-|ak_)[A-Za-z0-9_-]{8,}\b", "[疑似凭据已脱敏]"),
    ("系统用户目录", r"(?i)\b[A-Z]:\\Users\\[^\\\s]+", "%USERPROFILE%"),
]

# 非 A 级越界类别：KEEP_HINT 不得掩盖这些类别。
OUT_OF_SCOPE_CATEGORIES = ("获奖记录", "项目状态", "个人生活", "时效性")

DEFAULT_MANUAL_VERIFICATION_RECORD = os.path.join(REPORT_DIR, ".doubao-verification.json")

DEFAULT_OBLIGATION_PATHS = {
    "项目 AGENTS.md": os.path.join(BASE, "AGENTS.md"),
    "个人AI协议.md": PROTOCOL,
    "个人偏好.md": PROFILE,
    "DSH mem0-memory Skill": os.path.expandvars(r"%USERPROFILE%\.dsh\skills\mem0-memory\SKILL.md"),
    "WorkBuddy MEMORY.md": os.path.expandvars(r"%USERPROFILE%\.workbuddy\MEMORY.md"),
    "MiMO 全局 AGENTS.md": os.path.expandvars(r"%USERPROFILE%\.config\mimocode\AGENTS.md"),
    "MiMO 项目 AGENTS.md": os.path.join(BASE, "AGENTS.md"),
}

OBLIGATION_NEEDLES = {
    "项目 AGENTS.md": ("mem0 只保存 A 级", "任务收尾必须询问沉淀"),
    "个人AI协议.md": ("任务收尾的沉淀询问", "mem0"),
    "个人偏好.md": ("任务收尾的沉淀询问", "询问不等于写入"),
    "DSH mem0-memory Skill": ("任务收尾的沉淀询问", "不得自行 `delete_memory`"),
    "WorkBuddy MEMORY.md": ("任务收尾必须询问沉淀", "不自行删除或覆盖"),
    "MiMO 全局 AGENTS.md": ("任务收尾的沉淀询问", "不得自行删除或覆盖"),
    "MiMO 项目 AGENTS.md": ("mem0 只保存 A 级", "任务收尾必须询问沉淀"),
}

# 每个适用文件的治理合同检查：needles 为 (说明, 必需包含, 不得包含)。
# 否定句/历史说明若只以否定形式出现，会因“必需包含”缺失或“不得包含”命中而失败。
NEGATION_MARKERS = ("原表述", "曾经的假设", "早期假设", "已废止", "旧规则", "历史说明", "不再")

CONTRACT_CHECKS = {
    "项目 AGENTS.md": [
        ("Obsidian 权威优先级", ("个人偏好.md", "终极权威"), ()),
        ("mem0 只保存 A 级", ("mem0 只保存 A 级",), ()),
        ("B 级只进 Inbox", ("B 级", "Inbox"), ()),
        ("C 级禁止写入", ("C 级", "禁止"), ()),
        ("不得自行删除或覆盖", ("不得自行 `delete_memory`",), ()),
        ("任务收尾沉淀询问", ("任务收尾必须询问沉淀",), ()),
        ("会话开始主动报告待决事项", (".pending-alert.md",), ()),
    ],
    "个人AI协议.md": [
        ("Obsidian 权威优先级", ("权威源",), ()),
        ("mem0 只保存 A 级", ("稳定个人事实", "mem0"), ()),
        ("B 级只进 Inbox", ("B 级", "Inbox"), ()),
        ("C 级禁止写入", ("C 级", "禁止"), ()),
        ("不得自行删除或覆盖", ("不得自行删除或覆盖",), ()),
        ("收尾沉淀询问", ("任务收尾的沉淀询问",), ()),
        ("豆包不接入共享 mem0", ("豆包不接入共享 mem0",), ()),
    ],
    "个人偏好.md": [
        ("mem0 与权威源关系", ("个人偏好的权威版本",), ()),
        ("收尾沉淀询问", ("任务收尾的沉淀询问",), ()),
    ],
    "DSH mem0-memory Skill": [
        ("mem0 只保存 A 级", ("A 级", "可写入 mem0"), ()),
        ("B 级只进 Inbox", ("B 级", "Inbox"), ()),
        ("C 级禁止写入", ("C 级", "禁止"), ()),
        ("不得自行删除或覆盖", ("不得自行 `delete_memory`",), ()),
        ("写入后回读", ("回读确认",), ()),
        ("收尾沉淀询问", ("任务收尾的沉淀询问",), ()),
        ("豆包不接入共享 mem0", (), ("与 WorkBuddy、MiMO、豆包等共用同一份",)),
    ],
    "WorkBuddy MEMORY.md": [
        ("权威优先级与 mem0 关系", ("00-Profile", "mem0"), ()),
        ("不得自行删除或覆盖", ("不自行删除或覆盖",), ()),
        ("收尾沉淀询问", ("任务收尾必须询问沉淀",), ()),
        ("会话开始主动报告待决事项", (".pending-alert.md",), ()),
    ],
    "MiMO 全局 AGENTS.md": [
        ("mem0 只保存 A 级", ("仅存 A 级",), ()),
        ("B 级只进 Inbox", ("B 级", "Inbox"), ()),
        ("C 级禁止写入", ("C 级", "禁止"), ()),
        ("不得自行删除或覆盖", ("不得自行删除或覆盖",), ()),
        ("写入后回读", ("回读",), ()),
        ("收尾沉淀询问", ("任务收尾的沉淀询问",), ()),
        ("会话开始主动报告待决事项", (".pending-alert.md",), ()),
    ],
    "MiMO 项目 AGENTS.md": [
        ("mem0 只保存 A 级", ("mem0 只保存 A 级",), ()),
        ("C 级禁止写入", ("C 级", "禁止"), ()),
        ("不得自行删除或覆盖", ("不得自行 `delete_memory`",), ()),
        ("收尾沉淀询问", ("任务收尾必须询问沉淀",), ()),
    ],
}

DOUBAO_RECORD_REQUIRED = (
    "schema_version", "verified_at", "outcome", "scenario",
    "doubao_reply_evidence", "expected_authority", "observed_conclusion", "confirmed_by",
)
DOUBAO_RECORD_SCHEMA_VERSION = 1
DOUBAO_VERIFICATION_INTERVAL_DAYS = 90


def read_mem0():
    """从 SQLite history 只读重建活跃记录；不代表 MCP/向量索引实时集合。"""
    con = sqlite3.connect("file:%s?mode=ro" % DB.replace("\\", "/"), uri=True)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("""
        SELECT id, memory_id, old_memory, new_memory, event,
               created_at, updated_at, is_deleted
        FROM history ORDER BY created_at ASC, rowid ASC
    """)
    latest, order = {}, []
    for row in cur.fetchall():
        mid = row["memory_id"]
        if mid not in latest:
            order.append(mid)
        latest[mid] = dict(row)
    out = []
    for mid in order:
        row = latest[mid]
        if row["event"] == "DELETE" or row["is_deleted"]:
            continue
        out.append({
            "id": mid,
            "memory": row["new_memory"] or "",
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    con.close()
    return out


def is_a_level(text):
    low = text.lower()
    return any(h.lower() in low for h in KEEP_HINTS)


def _matches(rule_name, text):
    patterns = dict(RULES)[rule_name]
    return any(re.search(pattern, text, re.I) for pattern in patterns)


def sensitive_findings(text):
    """返回命中的敏感模式标签；分类与脱敏共用这一责任源。"""
    return [label for label, pattern, _ in SENSITIVE_PATTERNS if re.search(pattern, text, re.I)]


def _identity_keyword_hits(text):
    """结构化敏感模式之外的旧式身份关键词，仍应先于 A 级提示生效。"""
    return [pattern for pattern in dict(RULES)["身份泄漏"] if re.search(pattern, text, re.I)]


def _is_keep_hint_only(text, matched):
    """判断被命中的越界关键词是否只是 A 级提示自身的措辞。

    只有“该匹配片段本身是 KEEP_HINT 的一部分”时才算合法；整条记录仍不得豁免。
    """
    low = text.lower()
    return any(matched.lower() in hint.lower() and hint.lower() in low for hint in KEEP_HINTS)


def _out_of_scope_hits(text):
    """返回非 A 级越界类别；命中片段若纯属 A 级提示措辞则不计入。"""
    hits = []
    for name in OUT_OF_SCOPE_CATEGORIES:
        for pattern in dict(RULES)[name]:
            for match in re.finditer(pattern, text, re.I):
                if _is_keep_hint_only(text, match.group(0)):
                    continue
                hits.append(name)
                break
            else:
                continue
            break
    return hits


def _absolute_violation(text):
    """仅当整条记录不含合法豁免子句时，绝对词才视为需人工复核。"""
    if not _matches("绝对化", text):
        return False
    low = text.lower()
    if not any(e in low for e in ABSOLUTE_EXEMPT):
        return True
    # 合法豁免只保护它自己的子句：剔除豁免子句后仍有绝对词即需复核。
    remainder = low
    for exempt in ABSOLUTE_EXEMPT:
        remainder = remainder.replace(exempt, " ")
    return _matches("绝对化", remainder)


def classify(memories):
    """C 级隐私/凭据最优先；随后 A 级偏好；越界类别不得被 KEEP_HINT 掩盖。"""
    # 「绝对化」不是归属类别（其命中结果进入「限定词需核对」），故不建桶。
    buckets = {name: [] for name, _ in RULES if name != "绝对化"}
    for extra in ("限定词需核对", "需人工分类", "混合内容需拆分"):
        buckets[extra] = []
    keep = []

    def place(item, category, why):
        marked = dict(item)
        marked["_why"] = why
        buckets[category].append(marked)

    for item in memories:
        text = item["memory"]

        # 1) C 级隐私/凭据：结构化敏感模式与旧式身份关键词最优先，禁止落入 keep。
        findings = sensitive_findings(text)
        if findings:
            place(item, "身份泄漏" if "邮箱等可识别标识" in findings or "证件号码" in findings else "凭据/密钥",
                  "；".join(findings))
            continue
        identity_hits = _identity_keyword_hits(text)
        if identity_hits:
            place(item, "身份泄漏", "命中身份关键词：" + "、".join(identity_hits[:3]))
            continue

        hinted = is_a_level(text)

        # 2) 非 A 级越界类别：只有命中片段纯属 A 级提示措辞时才不算越界。
        out_of_scope_hits = _out_of_scope_hits(text)

        if out_of_scope_hits:
            if hinted:
                place(item, "混合内容需拆分", "同时含 A 级偏好线索与：" + "、".join(sorted(set(out_of_scope_hits))))
            else:
                place(item, out_of_scope_hits[0], out_of_scope_hits[0])
            continue

        if hinted:
            if _absolute_violation(text):
                place(item, "限定词需核对", "含绝对词，需核对是否为用户原意")
            else:
                keep.append(item)
            continue

        if _absolute_violation(text):
            place(item, "限定词需核对", "含绝对词且无 A 级偏好线索")
            continue

        place(item, "需人工分类", "无法从保守规则确认其为 A 级")

    return buckets, keep


def read_profile():
    if not os.path.exists(PROFILE):
        return "", set()
    with open(PROFILE, "r", encoding="utf-8") as stream:
        text = stream.read()
    ids = set(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text))
    return text, ids


def inbox_backlog():
    out = []
    if not os.path.isdir(INBOX):
        return out
    for filename in sorted(os.listdir(INBOX)):
        if not filename.endswith(".md") or filename == "README.md":
            continue
        path = os.path.join(INBOX, filename)
        with open(path, "r", encoding="utf-8") as stream:
            lines = stream.read().splitlines()
        rows, dates = 0, []
        for line in lines:
            if not line.strip().startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 4 or set(cells[0]) <= set("-: "):
                continue
            if "待审核" in cells:
                rows += 1
                match = re.match(r"(\d{4}-\d{2}-\d{2})", cells[0])
                if match:
                    dates.append(match.group(1))
        if rows:
            out.append((filename, rows, min(dates) if dates else "?"))
    return out


def _check_contract(label, text):
    """返回 (缺失合同说明列表, 冲突合同说明列表)。"""
    missing, conflicts = [], []
    for name, required, forbidden in CONTRACT_CHECKS.get(label, []):
        if any(word in text for word in NEGATION_MARKERS) and not all(item in text for item in required):
            missing.append(name)
            continue
        if any(item not in text for item in required):
            missing.append(name)
        for bad in forbidden:
            if bad in text:
                conflicts.append("合同「%s」被禁止表述违反：文件中出现「%s」" % (name, bad))
    return missing, conflicts


def check_obligations(paths=None):
    """读取每个真实规则文件，检查关键治理合同在位情况（静态证据，不等于行为合规）。"""
    paths = DEFAULT_OBLIGATION_PATHS if paths is None else paths
    results = {}
    for label, path in paths.items():
        path = os.fspath(path)
        if not os.path.isfile(path):
            results[label] = {
                "status": "missing", "required_ok": False,
                "detail": "文件缺失", "path": path,
            }
            continue
        try:
            with open(path, "r", encoding="utf-8") as stream:
                text = stream.read()
        except (OSError, UnicodeError) as exc:
            results[label] = {
                "status": "unreadable", "required_ok": False,
                "detail": "无法以 UTF-8 读取：%s" % type(exc).__name__, "path": path,
            }
            continue

        missing, conflicts = _check_contract(label, text)

        status = "conflict" if conflicts else ("ok" if not missing else "missing_rule")
        parts = []
        if missing:
            parts.append("缺少关键合同：" + "；".join(missing))
        if conflicts:
            parts.append("发现冲突表述：" + "；".join(conflicts))
        results[label] = {
            "status": status,
            "required_ok": status == "ok",
            "detail": "静态检查：文件存在且关键合同在位（语义仍须行为测试）" if status == "ok" else "；".join(parts),
            "path": path,
        }

    results["豆包云端指引"] = _check_doubao_record(DEFAULT_MANUAL_VERIFICATION_RECORD)
    return results


def _check_doubao_record(manual_record):
    """仅当记录含固定 schema、可复核证据引用与人工确认时才认为验证仍在周期内。"""
    base = {
        "status": "manual", "required_ok": False, "verification_due": True, "path": None,
    }
    if not os.path.isfile(manual_record):
        base["detail"] = "无人工验证记录：云端指引持续有效性未经证明"
        return base
    base["path"] = manual_record
    try:
        with open(manual_record, "r", encoding="utf-8") as stream:
            record = json.load(stream)
        if not isinstance(record, dict):
            raise ValueError("record is not an object")
        absent = [key for key in DOUBAO_RECORD_REQUIRED if not str(record.get(key, "")).strip()]
        if record.get("schema_version") != DOUBAO_RECORD_SCHEMA_VERSION:
            base["detail"] = "验证记录 schema_version 不是 %d，需重新验证" % DOUBAO_RECORD_SCHEMA_VERSION
            return base
        if absent:
            base["detail"] = "验证记录缺少字段：" + "、".join(absent)
            return base
        if record.get("outcome") != "pass":
            base["detail"] = "验证记录 outcome 非 pass，需重新验证"
            return base
        verified_at = datetime.fromisoformat(str(record["verified_at"]).replace("Z", "+00:00"))
        now = datetime.now(verified_at.tzinfo) if verified_at.tzinfo else datetime.now()
        age_days = (now - verified_at).days
        if not 0 <= age_days < DOUBAO_VERIFICATION_INTERVAL_DAYS:
            base["detail"] = "验证记录时间戳不合理或已超出 %d 天复核周期" % DOUBAO_VERIFICATION_INTERVAL_DAYS
            return base
        evidence = str(record["doubao_reply_evidence"])
        evidence_ok = bool(re.search(r"[0-9a-fA-F]{64}", evidence)) or os.path.isfile(evidence)
        if not evidence_ok:
            base["detail"] = "验证记录证据不可复核（需本地文件路径或 SHA-256）"
            return base
        base["verification_due"] = False
        base["detail"] = "存在可复核的人工验证记录（距今 %d 天）；记录仅代表有价值验证证据" % age_days
        return base
    except (OSError, ValueError, TypeError, KeyError):
        base["detail"] = "验证记录格式无效，需重新人工验证"
        return base


def _redact_text(text):
    for _, pattern, replacement in SENSITIVE_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text


def _safe_memory_text(item, category, limit=200):
    """按类别生成可决策且不泄露 C 级值的报告摘要。"""
    text = item.get("memory", "")
    if category in SENSITIVE_TYPES:
        return "[敏感内容已屏蔽：类别=%s；建议=立即由用户决定处置，不得复制或转述原文]" % category
    safe = _redact_text(text.replace("|", "\\|").replace("\n", " "))
    if category == "混合内容需拆分":
        return "同时含 A 级偏好线索与越界事实；需拆分后分别处置。安全摘要：%s" % _clip(safe, limit)
    if category == "限定词需核对":
        return "待核对限定词（绝对词：%s）。安全摘要：%s" % (
            "、".join(sorted(set(re.findall(r"绝不|一律|必须|总是|永远|严禁|不得|\bonly\b|\balways\b|\bnever\b|\bmust\b", text, re.I)))),
            _clip(safe, limit),
        )
    if category == "需人工分类":
        return "无法自动判定归属，需人工分类。安全语义摘要：%s" % _clip(safe, limit)
    return _clip(safe, limit)


def _clip(text, limit):
    return text if len(text) <= limit else text[:limit] + "…"


def _display_path(path):
    if not path:
        return "本地无可验证文件"
    shown = re.sub(r"(?i)\b[A-Z]:\\Users\\[^\\]+", "%USERPROFILE%", os.path.abspath(path))
    return shown


def _rule_status_text(result):
    return {
        "ok": "OK",
        "manual": "需人工验证",
        "missing": "文件缺失",
        "missing_rule": "规则缺失",
        "conflict": "规则冲突",
        "unreadable": "无法读取",
    }.get(result.get("status"), "未知")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass
    quiet = "--quiet" in sys.argv
    memories = read_mem0()
    buckets, keep = classify(memories)
    _, profile_ids = read_profile()
    memory_ids = {item["id"] for item in memories}
    unreferenced = sorted(memory_ids - profile_ids)
    explicit_missing = sorted(profile_ids - memory_ids)
    obligations = check_obligations()
    backlog = inbox_backlog()

    now = datetime.now()
    review = buckets["限定词需核对"]
    manual = buckets["需人工分类"]
    out_of_scope = sum(
        len(buckets[name]) for name, _ in RULES if name != "绝对化"
    )

    lines = []
    add = lines.append
    add("# 漂移检测报告")
    add("")
    add("> 由 `tools\\drift_check.py` 自动生成（全程只读）。")
    add("> 生成时间：%s" % now.strftime("%Y-%m-%d %H:%M:%S"))
    add("")
    add("## 摘要")
    add("")
    add("| 指标 | 值 | 证据类型 |")
    add("|------|-----|----------|")
    add("| history 重建活跃数 | **%d** | SQLite history 推导，不等于实时集合 |" % len(memories))
    add("| MCP/向量索引实时集合数量 | **未测量/未知** | 本脚本未连接实时集合 |")
    add("| 越界（非 A 级偏好，应迁出） | **%d** | 规则匹配 |" % out_of_scope)
    add("| 疑似已确认 A 级偏好（保留） | %d | 保守关键词匹配 |" % len(keep))
    add("| 未知/需人工分类 | %d | 无法自动确认归属 |" % len(manual))
    add("| 含绝对词、需人工核对限定词 | %d | 规则匹配 |" % len(review))
    add("| 权威源显式引用 ID | %d | 文本 UUID 提取 |" % len(profile_ids))
    add("| ID 未在权威源显式引用（信息性） | %d | 集合差 |" % len(unreferenced))
    add("| 权威源显式引用 ID 缺失 | %d | 集合差 |" % len(explicit_missing))
    add("")
    add("> **范围声明：未执行全文语义同步校验。** UUID 集合差不能证明内容层面的完整同步。")
    add("")
    add("✅ **无越界记忆。**" if out_of_scope == 0 else "⚠️ **存在 %d 条越界记忆，仅提出建议，不自动清理。**" % out_of_scope)
    add("")

    add("### 按类型分布")
    add("")
    add("| 类型 | 条数 |")
    add("|------|------|")
    for name, items in buckets.items():
        if items:
            add("| %s | %d |" % (name, len(items)))
    add("")

    for name, items in buckets.items():
        if not items:
            continue
        add("## %s（%d 条）" % (name, len(items)))
        add("")
        add("| # | 稳定标识 | 内容/安全摘要 | 建议 |")
        add("|---|----------|---------------|------|")
        for index, item in enumerate(items, 1):
            if name in ("身份泄漏", "获奖记录", "个人生活"):
                suggestion = "经用户批准后迁出；本脚本不修改"
            elif name == "项目状态":
                suggestion = "经批准后迁至 `01-Projects\\`"
            elif name == "时效性":
                suggestion = "人工判断是否进入项目状态文件"
            elif name == "限定词需核对":
                suggestion = "逐词核对限定词，不自动删除"
            elif name == "凭据/密钥":
                suggestion = "停止传播并由用户决定后续处置"
            else:
                suggestion = "人工分类，不得自动认定 A 级"
            add("| %d | `%s` | %s | %s |" % (
                index, item["id"], _safe_memory_text(item, name), suggestion
            ))
        add("")

    add("## 保留候选（疑似已确认 A 级偏好，%d 条）" % len(keep))
    add("")
    for item in keep:
        add("- `%s` %s" % (item["id"], _safe_memory_text(item, "保留")))
    add("")

    if unreferenced:
        add("## ID 未在权威源显式引用（信息性，非错误）")
        add("")
        add("> 仅表示 UUID 未写入 `个人偏好.md`；不代表对应内容缺失。")
        add("")
        for item_id in unreferenced:
            add("- `%s`" % item_id)
        add("")
    if explicit_missing:
        add("## 权威源显式引用 ID 缺失")
        add("")
        add("> 这是显式 UUID 引用检查；**未执行全文语义同步校验**。")
        add("")
        for item_id in explicit_missing:
            add("- `%s`" % item_id)
        add("")

    add("## 规则在位检查")
    add("")
    add("| 检查项 | 结果 | 证据 |")
    add("|--------|------|------|")
    for label, result in obligations.items():
        path = _display_path(result.get("path"))
        add("| %s | %s | %s；`%s` |" % (
            label, _rule_status_text(result), result.get("detail", ""), path.replace("|", "\\|")
        ))
    add("")
    add("> 规则检查不会读取或输出凭据文件。豆包云端配置无法由本地物理证据证明。")
    add("")

    add("## Inbox 积压")
    add("")
    if backlog:
        add("| 文件 | 待审核条数 | 最早日期 |")
        add("|------|-----------|---------|")
        for filename, count, date in backlog:
            add("| %s | %d | %s |" % (filename, count, date))
    else:
        add("无待审核候选。")
    add("")

    report = "\n".join(lines)
    print("=" * 68)
    print("漂移检测摘要")
    print("=" * 68)
    print("history 重建活跃数       : %d" % len(memories))
    print("实时集合数量未测量/未知")
    print("越界（应迁出）           : %d" % out_of_scope)
    print("疑似已确认 A 级偏好      : %d" % len(keep))
    print("未知/需人工分类          : %d" % len(manual))
    print("需核对限定词             : %d" % len(review))
    print("权威源显式引用 ID 缺失   : %d" % len(explicit_missing))
    print("未执行全文语义同步校验")
    for label, result in obligations.items():
        print("规则 %-24s: %s" % (label, _rule_status_text(result)))
    if backlog:
        print("Inbox 积压:")
        for filename, count, date in backlog:
            print("  - %s: %d 条（最早 %s）" % (filename, count, date))
    else:
        print("Inbox 积压              : 无")

    if not quiet:
        os.makedirs(REPORT_DIR, exist_ok=True)
        output = os.path.join(REPORT_DIR, "漂移检测-%s.md" % now.strftime("%Y%m%d-%H%M%S"))
        with open(output, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(report)
        print("-" * 68)
        print("报告已写入: %s" % output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
