# -*- coding: utf-8 -*-
"""每周体检运行器：只读检查源数据（mem0/Qdrant/账本/规则文件）；
默认把报告写到 `Inbox\\_reports\\`（.pending-alert.md/.audit-state.json）——
**不改任何记忆数据或 Inbox 行**。`--dry-run` 时连报告也不写，纯打印。"""
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drift_check as dc  # noqa: E402

REPORT_DIR = dc.REPORT_DIR
STATE = os.path.join(REPORT_DIR, ".audit-state.json")
ALERT = os.path.join(REPORT_DIR, ".pending-alert.md")
STALE_DAYS = 7

MANUAL_DUE_ADVICE = {
    "豆包云端指引": "在受控对话中实测豆包是否仍引用权威源修正版口径，再由用户确认后写入验证记录",
}


def _safe_candidate_summary(text):
    """字段级脱敏后可决策摘要：保留技术语义，屏蔽凭据值。"""
    if dc.sensitive_findings(text):
        return "[该候选含敏感模式（%s）：仅提示类别与建议=由 Agent 在受控源核实后私下向用户报告，不得写入二级报告]" % "、".join(dc.sensitive_findings(text))
    text = text.replace("|", "\\|").replace("\n", " ").strip()
    text = dc._redact_text(text)
    return text if len(text) <= 320 else text[:320] + "…（余文未复制）"


def inbox_candidates():
    """提取待审核候选，附文件与行号；不改变真实 Inbox。"""
    out = []
    if not os.path.isdir(dc.INBOX):
        return out
    for filename in sorted(os.listdir(dc.INBOX)):
        if not filename.endswith(".md") or filename == "README.md":
            continue
        path = os.path.join(dc.INBOX, filename)
        with open(path, "r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip().startswith("|"):
                    continue
                cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                if len(cells) < 4 or set(cells[0]) <= set("-: ") or "待审核" not in cells:
                    continue
                content = max(cells, key=len)
                out.append({
                    "file": filename,
                    "line": line_number,
                    "date": cells[0],
                    "content": _safe_candidate_summary(content),
                    "sensitive": bool(dc.sensitive_findings(content)),
                })
    return out


def days_since(iso):
    try:
        return (datetime.now() - datetime.fromisoformat(iso)).days
    except Exception:
        return None


def _rule_groups(obligations):
    failures = []
    manual_due = []
    for label, result in obligations.items():
        status = result.get("status")
        if status == "manual":
            if result.get("verification_due", False):
                manual_due.append((label, result))
        elif status == "not_applicable":
            continue  # 该 Agent/组件未接入本机，不是治理故障
        elif status != "ok":
            failures.append((label, result))
    return failures, manual_due


def _safe_memory_summary(item, category):
    return dc._safe_memory_text(item, category, limit=220)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass
    reconstructed = dc.read_mem0()
    health = dc.bridge_health()  # 单一入口：墓碑/实时点/幽灵/自愈留痕/冲突/失败删除（全只读）
    mem0_on = dc.mem0_available()  # False = 纯文件大脑模式，mem0 相关检查不适用
    buckets, keep = dc.classify(reconstructed)
    _, profile_ids = dc.read_profile()
    reconstructed_ids = {item["id"] for item in reconstructed}
    unreferenced = sorted(reconstructed_ids - profile_ids)
    # mem0 未接入时，权威源里对 mem0 UUID 的引用无从校验，不算缺失
    explicit_missing = sorted(profile_ids - reconstructed_ids) if mem0_on else []
    obligations = dc.check_obligations()
    backlog = dc.inbox_backlog()
    candidates = inbox_candidates()

    review = buckets.get("限定词需核对", [])
    manual_classification = buckets.get("需人工分类", [])
    mixed = buckets.get("混合内容需拆分", [])
    out_of_scope = []
    for name, _ in dc.RULES:
        if name == "绝对化":
            continue
        for item in buckets.get(name, []):
            out_of_scope.append({"id": item["id"], "why": name, "text": item["memory"]})

    rule_failures, manual_due = _rule_groups(obligations)
    now = datetime.now()
    prev_days = None
    if os.path.exists(STATE):
        try:
            with open(STATE, "r", encoding="utf-8") as stream:
                prev_days = days_since(json.load(stream).get("last_audit", ""))
        except (OSError, ValueError, TypeError):
            pass

    reasons = []
    if out_of_scope:
        reasons.append("权威活跃集合中有 %d 条越界候选" % len(out_of_scope))
    if health["ghosts"]:
        reasons.append("幽灵向量 %d 条：重启 mem0 桥后自动清除，未清除前请勿信任向量盘直读" % len(health["ghosts"]))
    if health["bridge_code"] == "old" and mem0_on:
        reasons.append("mcp_server.py 为旧版（无权威账本）——重启使用 mem0 的会话后生效")
    _unmeasurable = [k for k in ("conflicts", "failed_deletes", "orphan_pending") if health[k] is None]
    if not mem0_on:
        pass  # 纯文件大脑模式：桥运行态不适用，不报「不可测」
    elif _unmeasurable:
        reasons.append("桥运行态不可测（表未建/不可读：%s）——不得视为零" % "、".join(_unmeasurable))
    else:
        if health["conflicts"]:
            reasons.append("复活企图 %d 起（墓碑 id 被 ADD/UPDATE，将由自愈重删）" % health["conflicts"])
        if health["failed_deletes"]:
            reasons.append("删除失败 %d 条（见 delete_attempts）" % health["failed_deletes"])
        if health["orphan_pending"]:
            reasons.append("孤儿 pending 墓碑 %d 条（下次桥启动自动对账）" % health["orphan_pending"])
    if dc.registry_missing():
        reasons.append("已裁决保留注册表缺失——白名单豁免已整体停用，C 组重现属预期保护")
    if mixed:
        reasons.append("有 %d 条混合内容需拆分" % len(mixed))
    if manual_classification:
        reasons.append("有 %d 条未知/需人工分类" % len(manual_classification))
    if review:
        reasons.append("有 %d 条限定词待复核" % len(review))
    if explicit_missing:
        reasons.append("权威源显式引用 ID 缺失 %d 条" % len(explicit_missing))
    if candidates:
        reasons.append("Inbox 有 %d 条待审核候选" % len(candidates))
    if rule_failures:
        reasons.append("有 %d 项必需规则缺失、不可读或冲突" % len(rule_failures))
    if manual_due:
        reasons.append("有 %d 项需人工验证且已到验证周期" % len(manual_due))

    state = {
        "last_audit": now.isoformat(timespec="seconds"),
        "previous_audit_days_ago": prev_days,
        "stale": prev_days is None or prev_days >= STALE_DAYS,
        "authoritative_active_count": len(reconstructed),
        "live_collection_count": health["live_points"],
        "live_collection_measurement": (
            "Qdrant storage.sqlite 直读；活跃 = 实时点 − tombstone" if health["live_points"] is not None
            else "直读失败，history 兜底重建（墓碑仍已应用）"),
        "ghost_vectors": len(health["ghosts"]),
        "last_heal": health["last_heal"],
        "bridge_code_state": health["bridge_code"],
        "confirmed_keep_candidate_count": len(keep),
        "out_of_scope": len(out_of_scope),
        "mixed_content": len(mixed),
        "manual_classification": len(manual_classification),
        "needs_review": len(review),
        "ids_not_explicitly_referenced": len(unreferenced),
        "explicit_reference_ids_missing": len(explicit_missing),
        "semantic_sync_check": "未执行全文语义同步校验",
        "inbox_candidates": len(candidates),
        "required_rules_ok": not rule_failures,
        "manual_verification_due": len(manual_due),
        "pending_alert": bool(reasons),
        "alert_reasons": reasons,
    }

    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(STATE, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(state, stream, ensure_ascii=False, indent=2)
        stream.write("\n")

    lines = []
    add = lines.append
    add("# %s 记忆系统体检" % ("⚠️" if reasons else "✅"))
    add("")
    add("> 本文件由 `tools/weekly_audit.py` 自动生成。脚本不修改 mem0、Inbox 审核状态或治理规则。")
    add("")
    add("## 证据口径")
    add("")
    add("- 体检时间：%s" % now.strftime("%Y-%m-%d %H:%M"))
    add("- 已测量事实：Inbox 待审核 %d 条；本地规则文件逐项读取。" % len(candidates))
    if not mem0_on:
        add("- **运行模式：纯文件大脑**（mem0 未接入，`%s` 不存在）——权威层为 `knowledge/` 文件，"
            "mem0 相关检查（活跃集合/幽灵/桥账本/显式 ID 引用）本项不适用，不计入待决。" % dc.DB)
    else:
        add("- 权威活跃集合（实时点−墓碑）：**%d**；实时向量点数：%s（storage.sqlite 直读）。" % (
            len(reconstructed), health["live_points"] if health["live_points"] is not None else "直读失败"))
        add("- 幽灵向量（已批准删除仍在盘，桥重启自愈）：%d。" % len(health["ghosts"]))
    add("- 语义同步：**未执行全文语义同步校验**；仅做权威源显式 UUID 引用集合差。")
    add("- 需人工验证：%d 项（本地文件不能证明云端状态）。" % len(manual_due))
    add("- 距上次体检：%s" % ("首次" if prev_days is None else "%d 天" % prev_days))
    if mem0_on:
        add("- 已裁决保留注册表：%s。" % ("在位" if not dc.registry_missing() else "**缺失**（豁免层停用）"))
    add("")

    number = 0
    if out_of_scope:
        add("## A. 越界候选（仅建议，不自动清理）")
        add("")
        add("| # | 稳定标识 | 类型 | 安全摘要 | 建议 |")
        add("|---|----------|------|----------|------|")
        for item in out_of_scope:
            number += 1
            add("| %d | `%s` | %s | %s | 经用户批准后迁出对应文件；脚本不修改 |" % (
                number, item["id"], item["why"],
                _safe_memory_summary({"id": item["id"], "memory": item["text"]}, item["why"]),
            ))
        add("")

    if mixed:
        add("## B. 混合内容需拆分（含 A 级偏好 + 越界事实）")
        add("")
        add("| # | 稳定标识 | 安全摘要 | 建议 |")
        add("|---|----------|----------|------|")
        for item in mixed:
            number += 1
            add("| %d | `%s` | %s | 只保留偏好子句写回权威源；越界事实迁出，不得整体 keep |" % (
                number, item["id"], _safe_memory_summary(item, "混合内容需拆分"),
            ))
        add("")

    if manual_classification:
        add("## C. 未知/需人工分类")
        add("")
        add("| # | 稳定标识 | 安全摘要 | 建议 |")
        add("|---|----------|----------|------|")
        for item in manual_classification:
            number += 1
            add("| %d | `%s` | %s | 由 Agent 在受控源读取后向用户转述要点，再由用户判定 A/B/C |" % (
                number, item["id"], _safe_memory_summary(item, "需人工分类"),
            ))
        add("")

    if candidates:
        add("## D. Inbox 待审核候选（需用户决定批准/拒绝）")
        add("")
        add("| # | 来源定位 | 日期 | 决策摘要 | 建议 |")
        add("|---|----------|------|----------|------|")
        for candidate in candidates:
            number += 1
            if candidate.get("sensitive"):
                advice = "含敏感模式：不进入共享记忆，由用户决定删除或另行处置"
            else:
                advice = "批准=迁入「建议目标目录」并回读；拒绝=记录到拒绝清单；保留=留在 Inbox"
            add("| %d | `%s:%d` | %s | %s | %s |" % (
                number, candidate["file"], candidate["line"], candidate["date"],
                candidate["content"], advice,
            ))
        add("")

    if review:
        add("## E. 限定词待复核")
        add("")
        add("| # | 稳定标识 | 摘要 | 建议 |")
        add("|---|----------|------|------|")
        for item in review:
            number += 1
            add("| %d | `%s` | %s | 核对该绝对词是否为用户原意；是则保留原文，否则回改限定词 |" % (
                number, item["id"], _safe_memory_summary(item, "限定词需核对"),
            ))
        add("")

    if explicit_missing:
        add("## F. 权威源显式引用 ID 缺失")
        add("")
        add("> 只代表 UUID 集合差，**未执行全文语义同步校验**。")
        add("")
        for item_id in explicit_missing:
            number += 1
            add("%d. `%s` —— 建议：确认该 id 是否应重新写入 mem0 或从权威源移除引用" % (number, item_id))
        add("")

    if rule_failures:
        add("## G. 必需规则缺失、不可读或冲突")
        add("")
        for label, result in rule_failures:
            number += 1
            add("%d. **%s**：%s（`%s`）—— 建议：人工修复该规则文件后重跑体检" % (
                number, label, result.get("detail", result.get("status")), dc._display_path(result.get("path"))
            ))
        add("")

    if manual_due:
        add("## H. 需人工验证且已到周期")
        add("")
        for label, result in manual_due:
            number += 1
            add("%d. **%s**：%s —— 建议：%s" % (
                number, label, result.get("detail", "需人工验证"),
                MANUAL_DUE_ADVICE.get(label, "由用户在对话中确认该云端状态是否仍然有效"),
            ))
        add("")

    if not reasons:
        add("✅ **无待决事项。** 当前已测量范围内处于健康状态。")
        add("")

    add("---")
    add("")
    add("## Agent 报告说明")
    add("")
    add("> 直接在对话中概述待决项、建议与理由；不要让用户自行翻文件。")
    add("> 此报告只提供审计证据，不授权删除、迁移或修改记忆。")
    add("> 若某条标记为敏感或摘要不足，由 Agent 在受控源读取后于对话中转述，用户无需打开任何文件。")
    add("")

    with open(ALERT, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(lines))

    print("=" * 60)
    print("每周体检 · %s" % now.strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 60)
    print("权威活跃集合       : %d" % len(reconstructed))
    print("实时向量点数/幽灵  : %s / %d" % (health["live_points"], len(health["ghosts"])))
    print("越界候选           : %d" % len(out_of_scope))
    print("混合内容需拆分     : %d" % len(mixed))
    print("未知/需人工分类    : %d" % len(manual_classification))
    print("Inbox 待审核       : %d" % len(candidates))
    print("限定词待复核       : %d" % len(review))
    print("显式引用 ID 缺失   : %d" % len(explicit_missing))
    print("语义同步           : 未执行全文语义同步校验")
    print("必需规则缺失       : %d" % len(rule_failures))
    print("需人工验证到期     : %d" % len(manual_due))
    print("待决事项           : %s" % ("有" if reasons else "无"))
    for reason in reasons:
        print("  - %s" % reason)
    print("-" * 60)
    print("状态: %s" % STATE)
    print("告警: %s" % ALERT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
