# -*- coding: utf-8 -*-
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import drift_check as dc  # noqa: E402

TMP_ROOT = ROOT / ".tmp-tests"


class TempDir:
    """在项目工作区内创建受控临时目录，退出时彻底删除（不依赖 %TEMP%）。"""

    def __enter__(self):
        TMP_ROOT.mkdir(exist_ok=True)
        self.path = Path(tempfile_dir(TMP_ROOT))
        self.path.mkdir(parents=True, exist_ok=True)
        return self.path

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)
        return False


def tempfile_dir(parent):
    import uuid
    return parent / ("t-%s" % uuid.uuid4().hex[:12])


def memory(text, mid="11111111-1111-4111-8111-111111111111"):
    return {"id": mid, "memory": text, "created_at": None, "updated_at": None}


class ClassificationTests(unittest.TestCase):
    def test_identity_wins_over_preference_hint(self):
        buckets, keep = dc.classify([memory("John Doe prefers Simplified Chinese")])
        self.assertEqual(["11111111-1111-4111-8111-111111111111"], [m["id"] for m in buckets["身份泄漏"]])
        self.assertEqual([], keep)

    def test_credential_wins_over_powershell_hint(self):
        buckets, keep = dc.classify([memory("User uses PowerShell with API key sk-ABCDEFGH12345678")])
        self.assertEqual(1, len(buckets["凭据/密钥"]))
        self.assertEqual([], keep)

    def test_unknown_learning_fact_requires_manual_classification(self):
        buckets, keep = dc.classify([memory("User is studying an unfamiliar embedded-learning resource")])
        self.assertEqual(1, len(buckets["需人工分类"]))
        self.assertEqual([], keep)

    def test_confirmed_strong_constraint_is_not_out_of_scope(self):
        buckets, keep = dc.classify([memory("User requires explicit consent before any system configuration changes are made")])
        self.assertEqual(1, len(keep))
        self.assertFalse(any(buckets[name] for name, _ in dc.RULES if name != "绝对化"))

    def test_conditional_storage_preference_is_not_out_of_scope(self):
        buckets, keep = dc.classify([memory("User prefers E drive and will only use C drive when necessary after explicit confirmation")])
        retained = len(keep) + len(buckets["限定词需核对"])
        self.assertEqual(1, retained)
        self.assertFalse(any(buckets[name] for name, _ in dc.RULES if name != "绝对化"))

    def test_confirmed_read_only_preference_is_not_misread_as_project_status(self):
        buckets, keep = dc.classify([memory("User authorizes AI to perform read-only operations including retrieving project resources")])
        self.assertEqual(1, len(keep) + len(buckets["限定词需核对"]))
        self.assertEqual([], buckets["项目状态"])

    def test_confirmed_task_closure_rule_is_not_misread_as_personal_life(self):
        buckets, keep = dc.classify([memory("At task closure DSH, Doubao, WorkBuddy, and MiMO must ask whether to precipitate")])
        self.assertEqual(1, len(buckets["限定词需核对"]) + len(keep))
        self.assertEqual([], buckets["个人生活"])


class KeepHintDoesNotMaskOutOfScopeTests(unittest.TestCase):
    """Critical 1：KEEP_HINT 命中不得短路非 A 级越界检查。"""

    def assert_not_keep(self, text):
        buckets, keep = dc.classify([memory(text)])
        self.assertEqual([], keep, "混合记录不得判为 keep：%s" % text)
        return buckets

    def test_keep_hint_with_project_status(self):
        buckets = self.assert_not_keep("User prefers PowerShell and is currently learning for the 2026 iCAN competition")
        self.assertTrue(buckets["混合内容需拆分"])
        self.assertIn("项目状态", buckets["混合内容需拆分"][0]["_why"])

    def test_keep_hint_with_temporal_status(self):
        buckets = self.assert_not_keep("User prefers PowerShell and is currently learning for the 2026 iCAN competition")
        self.assertIn("时效性", buckets["混合内容需拆分"][0]["_why"])

    def test_keep_hint_with_award(self):
        buckets = self.assert_not_keep("User prefers Simplified Chinese and won the Blue Bridge championship")
        self.assertTrue(buckets["混合内容需拆分"])
        self.assertIn("获奖记录", buckets["混合内容需拆分"][0]["_why"])

    def test_keep_hint_with_personal_life(self):
        buckets = self.assert_not_keep("User prefers PowerShell and uses Valorant settings")
        self.assertTrue(buckets["混合内容需拆分"])
        self.assertIn("个人生活", buckets["混合内容需拆分"][0]["_why"])

    def test_keep_hint_with_deadline(self):
        buckets = self.assert_not_keep("User prefers Simplified Chinese and submits a project before the registration deadline")
        self.assertTrue(buckets["混合内容需拆分"])
        why = buckets["混合内容需拆分"][0]["_why"]
        self.assertTrue("项目状态" in why or "时效性" in why)


class SensitiveSharedSourceTests(unittest.TestCase):
    """Critical 2：分类检测与输出脱敏共用同一敏感模式源。"""

    def test_email_plus_preference_is_identity_risk(self):
        buckets, keep = dc.classify([memory("User email alice@example.com and prefers Simplified Chinese")])
        self.assertEqual([], keep)
        self.assertEqual(1, len(buckets["身份泄漏"]))

    def test_passport_plus_powershell_is_identity_risk(self):
        buckets, keep = dc.classify([memory("User passport number P1234567 and prefers PowerShell")])
        self.assertEqual([], keep)
        self.assertEqual(1, len(buckets["身份泄漏"]))

    def test_bearer_plus_preference_is_credential_risk(self):
        buckets, keep = dc.classify([memory("Authorization: Bearer abcdef123456 and prefers PowerShell")])
        self.assertEqual([], keep)
        self.assertEqual(1, len(buckets["凭据/密钥"]))

    def test_classifier_and_redactor_use_same_pattern_source(self):
        text = "alice@example.com and Authorization: Bearer abcdef123456"
        self.assertEqual(
            sorted(["邮箱等可识别标识", "Bearer 凭据"]),
            sorted(dc.sensitive_findings(text)),
        )
        # 同一来源必须也驱动脱敏：两者对同一输入保持一致判定。
        for label, pattern, _ in dc.SENSITIVE_PATTERNS:
            sample = "alice@example.com" if label == "邮箱等可识别标识" else None
            if sample is not None:
                self.assertIn(label, dc.sensitive_findings(sample))

    def test_unrecognized_identity_like_text_goes_manual_not_keep(self):
        buckets, keep = dc.classify([memory("User has an unfamiliar personal identifier listed somewhere")])
        self.assertEqual([], keep)
        self.assertEqual(1, len(buckets["需人工分类"]))


class AbsoluteExemptionScopeTests(unittest.TestCase):
    """Important 1：合法豁免只保护自己的子句，不覆盖整条记录。"""

    def test_exempt_clause_does_not_exempt_whole_record(self):
        buckets, keep = dc.classify([memory(
            "User requires explicit consent before configuration changes and always installs software on C drive"
        )])
        self.assertEqual([], keep)
        self.assertEqual(1, len(buckets["限定词需核对"]))

    def test_pure_exempt_clause_still_passes(self):
        buckets, keep = dc.classify([memory("User requires explicit consent before any system configuration changes are made")])
        self.assertEqual(1, len(keep))
        self.assertEqual([], buckets["限定词需核对"])


class ObligationTests(unittest.TestCase):
    def _full_contract_files(self, root):
        paths = {
            "项目 AGENTS.md": root / "AGENTS.md",
            "个人AI协议.md": root / "个人AI协议.md",
            "个人偏好.md": root / "个人偏好.md",
            "DSH mem0-memory Skill": root / "dsh-skill.md",
            "WorkBuddy MEMORY.md": root / "workbuddy.md",
            "MiMO 全局 AGENTS.md": root / "mimo-global.md",
            "MiMO 项目 AGENTS.md": root / "mimo-project.md",
        }
        bodies = {
            "项目 AGENTS.md": "个人偏好.md 是终极权威；A 级必须问用户；B 级直接写入正式目录；C 级禁止写入；Agent 不得自行删除或覆盖；分级自动沉淀；拿不准升 A；会话开始报告 .pending-alert.md",
            "个人AI协议.md": "权威源高于 mem0；A 级必须问用户；B 级直接写正式目录；C 级禁止写入；不得自行删除或覆盖；分级沉淀；拿不准升 A；破坏性操作红线；豆包不接入共享 mem0",
            "个人偏好.md": "本文件是个人偏好的权威版本；分级沉淀；破坏性操作红线已迁出到个人AI协议.md",
            "DSH mem0-memory Skill": "A 级可写入 mem0；B 级只能在 Inbox；C 级禁止写入；不得自行 `delete_memory`；写入后必须回读确认；任务收尾的沉淀询问",
            "WorkBuddy MEMORY.md": "以 00-Profile 为权威，mem0 为索引；不自行删除或覆盖；任务收尾必须询问沉淀；会话开始报告 .pending-alert.md",
            "MiMO 全局 AGENTS.md": "mem0 仅存 A 级；B 级进 Inbox；C 级禁止写入；不得自行删除或覆盖；写入后回读；任务收尾的沉淀询问；报告 .pending-alert.md",
            "MiMO 项目 AGENTS.md": "A 级必须问用户；C 级禁止写入；不得自行删除或覆盖；分级自动沉淀",
        }
        for label, path in paths.items():
            path.write_text(bodies[label], encoding="utf-8")
        return paths

    def test_missing_required_file_fails_rule_check(self):
        with TempDir() as root:
            paths = self._full_contract_files(root)
            # 2026-10-24：WorkBuddy/MiMO/Skill 属「未接入 Agent」，缺失报 not_applicable；
            # 真正的 missing 用非 optional 的项目 AGENTS.md 验证。
            paths["WorkBuddy MEMORY.md"].unlink()
            paths["项目 AGENTS.md"].unlink()
            result = dc.check_obligations(paths)
            self.assertEqual("not_applicable", result["WorkBuddy MEMORY.md"]["status"])
            self.assertTrue(result["WorkBuddy MEMORY.md"]["required_ok"])
            self.assertEqual("missing", result["项目 AGENTS.md"]["status"])
            self.assertFalse(result["项目 AGENTS.md"]["required_ok"])

    def test_files_existing_with_full_contracts_report_ok(self):
        with TempDir() as root:
            result = dc.check_obligations(self._full_contract_files(root))
            for label in ("项目 AGENTS.md", "个人AI协议.md", "个人偏好.md", "MiMO 全局 AGENTS.md"):
                self.assertEqual("ok", result[label]["status"], label)
            self.assertIn("语义仍须行为测试", result["项目 AGENTS.md"]["detail"])

    def test_negated_or_historical_mention_does_not_satisfy_contract(self):
        with TempDir() as root:
            paths = self._full_contract_files(root)
            paths["MiMO 全局 AGENTS.md"].write_text(
                "历史说明：旧规则曾要求 mem0 仅存 A 级，现已废止，不再执行。", encoding="utf-8",
            )
            result = dc.check_obligations(paths)
            self.assertNotEqual("ok", result["MiMO 全局 AGENTS.md"]["status"])
            self.assertFalse(result["MiMO 全局 AGENTS.md"]["required_ok"])

    def test_project_agents_md_does_not_masquerade_as_mimo_project_file(self):
        with TempDir() as root:
            paths = self._full_contract_files(root)
            paths["MiMO 项目 AGENTS.md"] = paths["项目 AGENTS.md"]
            paths["MiMO 项目 AGENTS.md"].write_text(
                "个人偏好.md 是终极权威；mem0 只保存 A 级；B 级追加到 Inbox；C 级禁止写入", encoding="utf-8",
            )
            result = dc.check_obligations(paths)
            self.assertNotEqual("ok", result["MiMO 项目 AGENTS.md"]["status"])

    def test_doubao_is_manual_not_ok(self):
        # 隔离：豆包判定与桥账本均不得读取生产文件（审计 #10：测试结果不能依赖用户目录现状）
        with TempDir() as root:
            with mock.patch.object(dc, "DEFAULT_MANUAL_VERIFICATION_RECORD", str(root / "absent.json")), \
                    mock.patch.object(dc, "bridge_health", return_value={
                        "bridge_code": "ok", "tombstones": 0, "live_points": 0,
                        "ghosts": [], "last_heal": None, "conflicts": 0,
                        "failed_deletes": 0, "orphan_pending": 0}), \
                    mock.patch.object(dc, "KEEP_REGISTRY_FILE", str(root / "registry.md")):
                (root / "registry.md").write_text(
                    "| id | fp |\n|---|---|\n", encoding="utf-8")  # 无 uuid 行→解析为空=None？改为含合法行
                result = dc.check_obligations({})
        self.assertEqual("manual", result["豆包云端指引"]["status"])
        self.assertFalse(result["豆包云端指引"]["required_ok"])
        self.assertTrue(result["豆包云端指引"]["verification_due"])

    def _write_doubao_record(self, path, **overrides):
        record = {
            "schema_version": 1,
            "verified_at": "2026-09-15T00:00:00",
            "outcome": "pass",
            "scenario": "询问能否装 C 盘",
            "doubao_reply_evidence": "inbox/doubao-reply-20260915.md",
            "expected_authority": "个人偏好.md 修正版口径",
            "observed_conclusion": "引用修正版口径，未读云端旧版",
            "confirmed_by": "用户人工确认",
        }
        record.update(overrides)
        path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        return path

    def test_doubao_record_requires_full_schema_positive_outcome_and_reviewable_evidence(self):
        with TempDir() as root:
            record = root / ".doubao-verification.json"
            evidence = root / "inbox" / "doubao-reply-20260915.md"
            evidence.parent.mkdir()
            evidence.write_text("豆包原始回复：应装 E 盘", encoding="utf-8")
            with mock.patch.object(dc, "DEFAULT_MANUAL_VERIFICATION_RECORD", str(record)):
                self.assertTrue(dc.check_obligations({})["豆包云端指引"]["verification_due"], "无记录应到期")

                self._write_doubao_record(record, schema_version=99, doubao_reply_evidence=str(evidence))
                self.assertTrue(dc.check_obligations({})["豆包云端指引"]["verification_due"], "schema 不符应到期")

                self._write_doubao_record(record, doubao_reply_evidence=str(evidence))
                for absent in ("scenario", "expected_authority", "observed_conclusion", "confirmed_by"):
                    self._write_doubao_record(record, doubao_reply_evidence=str(evidence), **{absent: ""})
                    self.assertTrue(dc.check_obligations({})["豆包云端指引"]["verification_due"], "%s 缺失应到期" % absent)

                self._write_doubao_record(record, outcome="fail", doubao_reply_evidence=str(evidence))
                self.assertTrue(dc.check_obligations({})["豆包云端指引"]["verification_due"], "失败验证应到期")

                self._write_doubao_record(record, doubao_reply_evidence="见上次对话")
                self.assertTrue(dc.check_obligations({})["豆包云端指引"]["verification_due"], "不可复核证据应到期")

    def test_doubao_record_with_sha256_evidence_is_accepted(self):
        with TempDir() as root:
            record = root / ".doubao-verification.json"
            digest = hashlib.sha256(b"doubao reply").hexdigest()
            self._write_doubao_record(record, doubao_reply_evidence="sha256:%s" % digest)
            with mock.patch.object(dc, "DEFAULT_MANUAL_VERIFICATION_RECORD", str(record)), \
                    mock.patch.object(dc, "datetime") as fake:
                fake.now.return_value = datetime(2026, 9, 16)
                fake.fromisoformat.side_effect = datetime.fromisoformat
                result = dc.check_obligations({})
            self.assertFalse(result["豆包云端指引"]["verification_due"])

    def test_doubao_record_rejects_future_and_stale_timestamps(self):
        with TempDir() as root:
            record = root / ".doubao-verification.json"
            evidence = root / "reply.md"
            evidence.write_text("reply", encoding="utf-8")
            with mock.patch.object(dc, "DEFAULT_MANUAL_VERIFICATION_RECORD", str(record)):
                self._write_doubao_record(record, verified_at="2999-01-01T00:00:00", doubao_reply_evidence=str(evidence))
                self.assertTrue(dc.check_obligations({})["豆包云端指引"]["verification_due"], "未来时间应到期")
                self._write_doubao_record(
                    record,
                    verified_at=(datetime.now() - timedelta(days=200)).isoformat(),
                    doubao_reply_evidence=str(evidence),
                )
                self.assertTrue(dc.check_obligations({})["豆包云端指引"]["verification_due"], "超周期应到期")

    def test_doubao_record_accepts_timezone_aware_timestamp(self):
        with TempDir() as root:
            record = root / ".doubao-verification.json"
            evidence = root / "reply.md"
            evidence.write_text("reply", encoding="utf-8")
            self._write_doubao_record(
                record, verified_at="2026-09-15T00:00:00+08:00", doubao_reply_evidence=str(evidence),
            )
            with mock.patch.object(dc, "DEFAULT_MANUAL_VERIFICATION_RECORD", str(record)), \
                    mock.patch.object(dc, "datetime") as fake:
                fake.now.return_value = datetime(2026, 9, 16, tzinfo=__import__("datetime").timezone.utc)
                fake.fromisoformat.side_effect = datetime.fromisoformat
                result = dc.check_obligations({})
            self.assertFalse(result["豆包云端指引"]["verification_due"])

    def test_external_dsh_skill_doubao_mem0_claim_is_reported_as_conflict(self):
        with TempDir() as root:
            paths = self._full_contract_files(root)
            paths["DSH mem0-memory Skill"].write_text(
                "A 级可写入 mem0；B 级只能在 Inbox；C 级禁止写入；不得自行 `delete_memory`；"
                "写入后必须回读确认；任务收尾的沉淀询问；与 WorkBuddy、MiMO、豆包等共用同一份",
                encoding="utf-8",
            )
            result = dc.check_obligations(paths)
            self.assertEqual("conflict", result["DSH mem0-memory Skill"]["status"])
            self.assertFalse(result["DSH mem0-memory Skill"]["required_ok"])

    def test_conflict_detail_quotes_the_forbidden_text_not_the_check_name(self):
        with TempDir() as root:
            paths = self._full_contract_files(root)
            paths["DSH mem0-memory Skill"].write_text(
                "A 级可写入 mem0；B 级只能在 Inbox；C 级禁止写入；不得自行 `delete_memory`；"
                "写入后必须回读确认；任务收尾的沉淀询问；与 WorkBuddy、MiMO、豆包等共用同一份",
                encoding="utf-8",
            )
            detail = dc.check_obligations(paths)["DSH mem0-memory Skill"]["detail"]
            # 必须引用真正出现在文件里的冲突原文。
            self.assertIn("与 WorkBuddy、MiMO、豆包等共用同一份", detail)

    def test_contract_check_requires_explicit_label(self):
        missing, conflicts = dc._check_contract("DSH mem0-memory Skill", "没有任何合同内容")
        self.assertTrue(missing)
        self.assertEqual([], conflicts)


class MetricLanguageTests(unittest.TestCase):
    def _make_history_db(self, path):
        con = sqlite3.connect(path)
        con.execute(
            "CREATE TABLE history (id TEXT, memory_id TEXT, old_memory TEXT, new_memory TEXT, event TEXT, created_at TEXT, updated_at TEXT, is_deleted INTEGER)"
        )
        con.execute(
            "INSERT INTO history VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("h1", "11111111-1111-4111-8111-111111111111", None, "User prefers Simplified Chinese", "ADD", "2026-01-01", None, 0),
        )
        con.commit()
        con.close()

    def test_keep_eligible_summary_stays_decidable(self):
        summary = dc._safe_memory_text(memory("User prefers Simplified Chinese for all replies"), "保留")
        self.assertIn("Simplified Chinese", summary)

    def test_decisional_summaries_never_contain_sensitive_values(self):
        cases = [
            ("Alice contacts user at alice@example.com", "身份泄漏"),
            ("User passport number P1234567", "身份泄漏"),
            ("User token=secret-value for PowerShell", "凭据/密钥"),
        ]
        for text, category in cases:
            summary = dc._safe_memory_text(memory(text), category)
            for leak in ("alice@example.com", "P1234567", "secret-value"):
                self.assertNotIn(leak, summary)

    def test_secret_in_non_sensitive_bucket_is_still_redacted(self):
        summary = dc._safe_memory_text(memory("User prefers PowerShell with token=secret-value"), "限定词需核对")
        self.assertNotIn("secret-value", summary)
        self.assertIn("PowerShell", summary)

    def test_accepted_keep_item_output_does_not_leak_getting_through(self):
        buckets, keep = dc.classify([memory("User prefers PowerShell and Simplified Chinese")])
        self.assertEqual(1, len(keep))
        self.assertEqual([], buckets["身份泄漏"])

    def test_external_user_home_path_is_sanitized(self):
        shown = dc._display_path(r"C:\Users\alice\.dsh\skills\mem0-memory\SKILL.md")
        self.assertTrue(shown.startswith("%USERPROFILE%"))
        self.assertNotIn("alice", shown)

    def test_bearer_and_windows_user_path_are_redacted(self):
        text = dc._redact_text(r"Authorization: Bearer abcdef123456 C:\Users\alice\secret.txt")
        self.assertNotIn("abcdef123456", text)
        self.assertNotIn("alice", text)

    def test_report_names_history_count_and_disclaims_live_and_semantic_measurement(self):
        with TempDir() as root:
            db = root / "mem0.db"
            profile = root / "个人偏好.md"
            inbox = root / "Inbox"
            report_dir = inbox / "_reports"
            inbox.mkdir()
            profile.write_text("# 个人偏好\n`22222222-2222-4222-8222-222222222222`\n", encoding="utf-8")
            self._make_history_db(db)
            with mock.patch.object(dc, "DB", str(db)), mock.patch.object(dc, "PROFILE", str(profile)), \
                    mock.patch.object(dc, "INBOX", str(inbox)), \
                    mock.patch.object(dc, "REPORT_DIR", str(report_dir)), \
                    mock.patch.object(dc, "QDRANT_DB", str(root / "absent-qdrant.sqlite")), \
                    mock.patch.object(dc, "LEDGER_DB", str(root / "absent-ledger.db")), \
                    mock.patch.object(dc, "check_obligations", return_value={}), \
                    mock.patch.object(sys, "argv", ["drift_check.py"]):
                output = StringIO()
                with redirect_stdout(output):
                    dc.main()
            report = next(report_dir.glob("漂移检测-*.md")).read_text(encoding="utf-8")
            combined = output.getvalue() + report
            # 2026-10-01（审计 #12）：向量不可读时 history 兜底重建，口径必须如实标注兜底。
            self.assertIn("权威活跃集合", combined)
            self.assertIn("兜底", combined)
            self.assertNotIn("history 重建活跃数", combined)
            self.assertIn("权威源显式引用 ID 缺失", combined)
            self.assertIn("未执行全文语义同步校验", combined)
            self.assertNotIn("mem0 当前条数", combined)
            self.assertNotIn("同步缺失（权威源引用、mem0 无）", combined)


if __name__ == "__main__":
    unittest.main()
