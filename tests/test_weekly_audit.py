# -*- coding: utf-8 -*-
import json
import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import weekly_audit as wa  # noqa: E402

TMP_ROOT = ROOT / ".tmp-tests"


class TempDir:
    """项目工作区内的受控临时目录；退出时删除，不依赖 %TEMP%。"""

    def __enter__(self):
        TMP_ROOT.mkdir(exist_ok=True)
        self.path = TMP_ROOT / ("t-%s" % uuid.uuid4().hex[:12])
        self.path.mkdir(parents=True, exist_ok=True)
        return self.path

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)
        return False


def memory(text="User prefers Simplified Chinese", mid="11111111-1111-4111-8111-111111111111"):
    return {"id": mid, "memory": text, "created_at": None, "updated_at": None}


def buckets(review=None, manual=None, mixed=None, out_of_scope=None):
    result = {name: [] for name, _ in wa.dc.RULES}
    result["限定词需核对"] = list(review or [])
    result["需人工分类"] = list(manual or [])
    result["混合内容需拆分"] = list(mixed or [])
    result["项目状态"] = list(out_of_scope or [])
    return result


def run_audit(case, *, bucket_data, keep=None, profile_ids=None, obligations=None, candidates=None):
    """共享运行器：注入合成 buckets，运行真实 weekly_audit.main。"""
    with TempDir() as root:
        report_dir = root / "reports"
        state = report_dir / ".audit-state.json"
        alert = report_dir / ".pending-alert.md"
        patches = [
            mock.patch.object(wa, "REPORT_DIR", str(report_dir)),
            mock.patch.object(wa, "STATE", str(state)),
            mock.patch.object(wa, "ALERT", str(alert)),
            mock.patch.object(wa.dc, "read_mem0", return_value=[memory()]),
            mock.patch.object(wa.dc, "classify", return_value=(bucket_data, keep or [])),
            mock.patch.object(wa.dc, "read_profile", return_value=("", set(profile_ids or []))),
            mock.patch.object(wa.dc, "check_obligations", return_value=obligations or {"project": {"status": "ok", "required_ok": True}}),
            mock.patch.object(wa.dc, "inbox_backlog", return_value=[]),
            mock.patch.object(wa, "inbox_candidates", return_value=candidates or []),
        ]
        for patch in patches:
            patch.start()
            case.addCleanup(patch.stop)
        wa.main()
        return json.loads(state.read_text(encoding="utf-8")), alert.read_text(encoding="utf-8")


class WeeklyAuditTests(unittest.TestCase):
    def run_audit(self, **kwargs):
        return run_audit(self, **kwargs)

    def test_only_qualifier_review_still_sets_pending_alert(self):
        state, alert = self.run_audit(bucket_data=buckets(review=[memory("User only uses C drive after explicit confirmation")]))
        self.assertTrue(state["pending_alert"])
        self.assertIn("限定词", " ".join(state["alert_reasons"]))
        self.assertNotIn("无待决事项", alert)

    def test_only_manual_classification_still_sets_pending_alert(self):
        state, alert = self.run_audit(bucket_data=buckets(manual=[memory("User is studying an unfamiliar resource")]))
        self.assertTrue(state["pending_alert"])
        self.assertIn("需人工分类", alert)

    def test_fully_clear_audit_is_healthy(self):
        state, alert = self.run_audit(bucket_data=buckets(), keep=[memory()])
        self.assertFalse(state["pending_alert"])
        self.assertIn("无待决事项", alert)

    def test_mixed_content_sets_pending_alert(self):
        item = memory("User prefers PowerShell and is currently learning for the 2026 iCAN competition")
        state, alert = self.run_audit(bucket_data=buckets(mixed=[item]))
        self.assertTrue(state["pending_alert"])
        self.assertIn("混合内容需拆分", alert)
        self.assertEqual(1, state["mixed_content"])

    def test_out_of_scope_only_sets_pending_alert(self):
        state, alert = self.run_audit(bucket_data=buckets(out_of_scope=[memory("temporary project status")]))
        self.assertTrue(state["pending_alert"])
        self.assertIn("越界候选", alert)

    def test_inbox_only_sets_pending_alert(self):
        candidate = {"file": "待审核.md", "line": 9, "date": "2026-01-01", "content": "synthetic candidate"}
        state, alert = self.run_audit(bucket_data=buckets(), keep=[memory()], candidates=[candidate])
        self.assertTrue(state["pending_alert"])
        self.assertIn("Inbox 待审核候选", alert)

    def test_state_uses_history_and_live_count_names(self):
        state, alert = self.run_audit(bucket_data=buckets(), keep=[memory()])
        self.assertIn("history_reconstructed_active_count", state)
        self.assertIn("live_collection_count", state)
        self.assertIsNone(state["live_collection_count"])
        self.assertNotIn("mem0_count", state)
        self.assertIn("实时集合数量：**未测量/未知**", alert)

    def test_explicit_reference_gap_is_not_called_semantic_sync(self):
        missing_id = "22222222-2222-4222-8222-222222222222"
        state, alert = self.run_audit(bucket_data=buckets(), keep=[memory()], profile_ids={missing_id})
        self.assertTrue(state["pending_alert"])
        self.assertIn("explicit_reference_ids_missing", state)
        self.assertIn("权威源显式引用 ID 缺失", alert)
        self.assertIn("未执行全文语义同步校验", alert)
        self.assertNotIn("同步缺失", alert)

    def test_manual_rule_due_sets_pending_alert(self):
        obligations = {"豆包云端指引": {"status": "manual", "required_ok": False, "verification_due": True, "detail": "需人工验证"}}
        state, alert = self.run_audit(bucket_data=buckets(), keep=[memory()], obligations=obligations)
        self.assertTrue(state["pending_alert"])
        self.assertIn("需人工验证", alert)

    def test_manual_rule_not_due_does_not_set_pending_alert(self):
        obligations = {"豆包云端指引": {"status": "manual", "required_ok": False, "verification_due": False, "detail": "需人工验证"}}
        state, alert = self.run_audit(bucket_data=buckets(), keep=[memory()], obligations=obligations)
        self.assertFalse(state["pending_alert"])
        self.assertIn("无待决事项", alert)

    def test_conflicting_required_rule_sets_pending_alert_and_names_conflict(self):
        obligations = {"DSH mem0-memory Skill": {"status": "conflict", "required_ok": False, "detail": "错误声称豆包接入共享 mem0", "path": "external-skill"}}
        state, alert = self.run_audit(bucket_data=buckets(), keep=[memory()], obligations=obligations)
        self.assertTrue(state["pending_alert"])
        self.assertIn("规则缺失、不可读或冲突", alert)

    def test_every_numbered_item_carries_advice(self):
        """每个编号事项都必须带建议，用户仅凭编号即可决策。"""
        obligations = {
            "豆包云端指引": {"status": "manual", "required_ok": False, "verification_due": True, "detail": "无人工验证记录"},
            "DSH mem0-memory Skill": {"status": "conflict", "required_ok": False, "detail": "冲突", "path": "skill"},
        }
        candidate = {"file": "待审核.md", "line": 9, "date": "2026-01-01", "content": "PowerShell 7 更快", "sensitive": False}
        state, alert = self.run_audit(
            bucket_data=buckets(review=[memory("User must confirm")], manual=[memory("unknown")]),
            obligations=obligations,
            candidates=[candidate],
        )
        numbered = [line for line in alert.splitlines() if line[:1].isdigit() or line.startswith("| ")]
        advice_lines = [line for line in alert.splitlines() if "建议" in line or "| 建议 |" in line or "建议目标" in line]
        self.assertTrue(numbered)
        self.assertGreaterEqual(len(advice_lines), 3)
        self.assertIn("建议", alert)
        self.assertNotIn("请用户打开源文件", alert)

    def test_section_headings_are_unique(self):
        obligations = {
            "豆包云端指引": {"status": "manual", "required_ok": False, "verification_due": True, "detail": "d"},
            "DSH mem0-memory Skill": {"status": "conflict", "required_ok": False, "detail": "c", "path": "p"},
        }
        _, alert = self.run_audit(bucket_data=buckets(manual=[memory("unknown")]), obligations=obligations)
        headings = [line for line in alert.splitlines() if line.startswith("## ")]
        self.assertEqual(len(headings), len(set(headings)), "报告不得出现重复章节标题：%s" % headings)


class DecidableCandidateSummaryTests(unittest.TestCase):
    """Important 4：普通候选必须可决策，敏感候选不得泄露。"""

    def test_plain_technical_candidate_keeps_decidable_semantics(self):
        summary = wa._safe_candidate_summary("PowerShell 7 启动更快，建议设为默认终端")
        self.assertIn("PowerShell", summary)
        self.assertIn("默认终端", summary)

    def test_sensitive_candidate_does_not_leak_values(self):
        summary = wa._safe_candidate_summary("联系邮箱 alice@example.com，token=secret-value")
        for leak in ("alice@example.com", "secret-value"):
            self.assertNotIn(leak, summary)
        self.assertIn("敏感", summary)

    def test_report_contains_advice_and_numbering(self):
        candidate = {
            "file": "待审核.md", "line": 9, "date": "2026-01-01",
            "content": "PowerShell 7 启动更快", "sensitive": False,
        }
        item = memory("User only uses C drive after explicit confirmation")
        _, text = run_audit(self, bucket_data=buckets(review=[item]), candidates=[candidate])
        self.assertIn("建议", text)
        self.assertIn("| 1 |", text)
        self.assertIn("| 2 |", text)
        self.assertNotIn("请用户打开源文件", text)
        self.assertNotIn("请自行核验", text)


class RealChainTests(unittest.TestCase):
    """Important 5：真实 history → 真实 classify → weekly_audit → 产物，全链路。"""

    def build_history(self, path, facts):
        import sqlite3
        con = sqlite3.connect(path)
        con.execute(
            "CREATE TABLE history (id TEXT, memory_id TEXT, old_memory TEXT, new_memory TEXT, event TEXT, created_at TEXT, updated_at TEXT, is_deleted INTEGER)"
        )
        for index, fact in enumerate(facts):
            con.execute(
                "INSERT INTO history VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("h%d" % index, "id-%d" % index, None, fact, "ADD", "2026-01-01T00:00:00", None, 0),
            )
        con.commit()
        con.close()

    def run_real_chain(self, facts, inbox_lines=()):
        with TempDir() as root:
            db = root / "mem0.db"
            profile = root / "个人偏好.md"
            inbox = root / "Inbox"
            report_dir = inbox / "_reports"
            inbox.mkdir()
            profile.write_text("# 个人偏好\n", encoding="utf-8")
            (inbox / "待审核.md").write_text("\n".join(inbox_lines), encoding="utf-8")
            self.build_history(db, facts)
            (root / "AGENTS.md").write_text(
                "个人偏好.md 是终极权威；mem0 只保存 A 级；B 级追加到 Inbox；C 级禁止写入；"
                "Agent 不得自行 `delete_memory`；任务收尾必须询问沉淀；会话开始报告 .pending-alert.md",
                encoding="utf-8",
            )
            # 使用真实规则检查与真实豆包验证记录判定，不 mock 掉判定逻辑。
            obligations = wa.dc.check_obligations({"项目 AGENTS.md": root / "AGENTS.md"})
            obligations["豆包云端指引"] = wa.dc._check_doubao_record(str(root / "missing-verification.json"))
            with mock.patch.object(wa.dc, "DB", str(db)), \
                    mock.patch.object(wa.dc, "PROFILE", str(profile)), \
                    mock.patch.object(wa.dc, "INBOX", str(inbox)), \
                    mock.patch.object(wa.dc, "REPORT_DIR", str(report_dir)), \
                    mock.patch.object(wa, "REPORT_DIR", str(report_dir)), \
                    mock.patch.object(wa, "STATE", str(report_dir / ".audit-state.json")), \
                    mock.patch.object(wa, "ALERT", str(report_dir / ".pending-alert.md")), \
                    mock.patch.object(wa.dc, "check_obligations", return_value=obligations):
                wa.main()
            state = json.loads((report_dir / ".audit-state.json").read_text(encoding="utf-8"))
            alert = (report_dir / ".pending-alert.md").read_text(encoding="utf-8")
            return state, alert

    def test_real_chain_flags_all_ten_regressions(self):
        facts = [
            "User prefers PowerShell and is currently learning for the 2026 iCAN competition",
            "User prefers Simplified Chinese and won the Blue Bridge championship",
            "User prefers PowerShell and uses Valorant settings",
            "User prefers Simplified Chinese and submits a project before the registration deadline",
            "User prefers PowerShell and email is alice@example.com",
            "User requires explicit consent before configuration changes and always installs software on C drive",
        ]
        inbox_lines = [
            "| 日期 | 来源 Agent | 候选类型 | 候选内容 | 证据/上下文 | 建议目标目录 | 状态 | 用户决定 |",
            "|---|---|---|---|---|---|---|---|",
            "| 2026-01-01 | DSH | 技术结论 | PowerShell 7 启动更快，建议设为默认终端 | 实测 | 02-Knowledge | 待审核 |  |",
            "| 2026-01-02 | DSH | 偏好 | token=secret-value 可直接写入共享记忆 | 实测 | 00-Profile | 待审核 |  |",
        ]
        state, alert = self.run_real_chain(facts, inbox_lines)

        # 1-4：KEEP_HINT 不得掩盖项目状态/获奖/个人生活/时效性 → 全部落入混合内容。
        self.assertGreaterEqual(state["mixed_content"], 4)
        # 5：邮箱进入身份风险，且不出现明文。
        self.assertNotIn("alice@example.com", alert)
        self.assertNotIn("secret-value", alert)
        # 6：合法豁免不得覆盖整条记录 → 限定词复核。
        self.assertGreaterEqual(state["needs_review"], 1)
        # 7/8：普通候选可决策；敏感候选不泄露。
        self.assertIn("PowerShell", alert)
        self.assertIn("建议", alert)
        # 9：规则状态来自真实 check_obligations（此处为 ok），不得伪装成行为合规。
        self.assertTrue(state["required_rules_ok"])
        # 10：豆包必须仍是 manual due（无验证记录）。
        self.assertGreaterEqual(state["manual_verification_due"], 1)
        self.assertTrue(state["pending_alert"])
        # 用户不需要打开源文件。
        self.assertNotIn("请用户打开源文件", alert)
        self.assertIn("未执行全文语义同步校验", alert)


class RealRuleCheckTests(unittest.TestCase):
    """Important 2 + 10：用真实 check_obligations 验证规则与豆包边界。"""

    def test_negation_only_rule_text_is_not_ok_and_keeps_alert(self):
        with TempDir() as root:
            paths = {
                "MiMO 全局 AGENTS.md": root / "mimo.md",
            }
            paths["MiMO 全局 AGENTS.md"].write_text(
                "历史说明：旧版本曾要求 mem0 仅存 A 级，现不再执行。", encoding="utf-8",
            )
            obligations = wa.dc.check_obligations(paths)
            self.assertNotEqual("ok", obligations["MiMO 全局 AGENTS.md"]["status"])

    def test_unreviewable_doubao_evidence_cannot_suppress_alert(self):
        with TempDir() as root:
            record = root / ".doubao-verification.json"
            record.write_text(json.dumps({
                "schema_version": 1,
                "verified_at": "2026-09-15T00:00:00",
                "outcome": "pass",
                "scenario": "scenario",
                "doubao_reply_evidence": "pasted into chat",
                "expected_authority": "expected",
                "observed_conclusion": "observed",
                "confirmed_by": "self",
            }, ensure_ascii=False), encoding="utf-8")
            with mock.patch.object(wa.dc, "DEFAULT_MANUAL_VERIFICATION_RECORD", str(record)):
                obligations = wa.dc.check_obligations({})
            result = obligations["豆包云端指引"]
            self.assertTrue(result["verification_due"])
            self.assertFalse(result["required_ok"])


if __name__ == "__main__":
    unittest.main()
