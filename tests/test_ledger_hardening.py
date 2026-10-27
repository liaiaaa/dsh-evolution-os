# -*- coding: utf-8 -*-
"""注册表硬化与桥对账回归测试。

2026-10-01 二次复验闭合 #1~#4；2026-10-03 三轮复验补 P0 防线：
delete_memory **端到端**主路径回归（成功必留已确认墓碑 / 失败必无墓碑 /
在飞 pending 不得被本次前置 heal 撤销）——旧测试只测辅助函数，
正是「65/65 全绿仍放走 P0」的教训固化。
"""
import importlib.util
import sys
import time
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import drift_check as dc  # noqa: E402

BRIDGE_SRC = r"E:\software\mem0-data\mcp_server.py"


def tmp_id():
    return str(uuid.uuid4())


class TempDir:
    def __enter__(self):
        self.path = ROOT / ".tmp-tests" / ("t-" + uuid.uuid4().hex[:12])
        self.path.mkdir(parents=True)
        return self.path

    def __exit__(self, *exc):
        import shutil
        shutil.rmtree(self.path, ignore_errors=True)
        return False


def memory(text, mid=None):
    return {"id": mid or tmp_id(), "memory": text, "created_at": None, "updated_at": None}


def _write_registry(path, rows):
    body = "# 注册表\n\n| mem0 id | 指纹(sha256前12) | 裁决来源 | 一句话理由 |\n|---|---|---|---|\n"
    for mid, fp in rows:
        body += "| `%s` | %s | t | t |\n" % (mid, ("`%s`" % fp) if fp else "—")
    path.write_text(body, encoding="utf-8")


class RegistryExemptionTests(unittest.TestCase):
    def test_fingerprint_match_exempts_content_drift_reports(self):
        text = "User prefers pending decisions as clickable options"
        mid = tmp_id()
        with TempDir() as root:
            reg = root / "registry.md"
            _write_registry(reg, [(mid, dc._fp12(text))])
            with mock.patch.object(dc, "KEEP_REGISTRY_FILE", str(reg)):
                self.assertTrue(dc.registry_exempt(mid, text))
                self.assertFalse(dc.registry_exempt(mid, text + "（被 mem0 改写）"))
                buckets, keep = dc.classify([memory(text, mid)])
                self.assertEqual([mid], [x["id"] for x in keep])
                buckets2, keep2 = dc.classify([memory(text + "（被 mem0 改写）", mid)])
                self.assertEqual([], keep2)
                self.assertTrue(any(mid == x["id"] for x in buckets2["需人工分类"]))

    def test_empty_fingerprint_row_not_exempted(self):
        mid = tmp_id()
        with TempDir() as root:
            reg = root / "registry.md"
            _write_registry(reg, [(mid, "")])
            with mock.patch.object(dc, "KEEP_REGISTRY_FILE", str(reg)):
                self.assertFalse(dc.registry_exempt(mid, "anything"))

    def test_missing_registry_disables_all_exemptions_and_is_reported(self):
        sample = dc.USER_CONFIRMED_KEEP[0]
        with TempDir() as root:
            with mock.patch.object(dc, "KEEP_REGISTRY_FILE", str(root / "nope.md")):
                self.assertFalse(dc.registry_exempt(sample, "whatever text"))
                self.assertTrue(dc.registry_missing())
                self.assertEqual(set(), dc.read_registry())
                obligations = dc.check_obligations({})
                reg_result = obligations["已裁决保留注册表"]
                self.assertFalse(reg_result["required_ok"])
                self.assertIn("停用", reg_result["detail"])

    def test_registry_covers_all_legacy_ids(self):
        if dc.registry_missing():
            self.skipTest("注册表文件不存在（独立发布包不含 knowledge/），本用例需完整 vault 环境")
        obligations = dc.check_obligations({})
        result = obligations["已裁决保留注册表"]
        self.assertTrue(result["required_ok"],
                        "兜底清单有条目未入注册表：%s" % result["detail"])


class ReadMem0DeletionScanTests(unittest.TestCase):
    """二次复验 #4：ADD→DELETE→ADD（复活痕迹）必须被任意行扫描捕获。"""

    def _make_history(self, path, ops):
        import sqlite3
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE history (id TEXT, memory_id TEXT, old_memory TEXT, "
                    "new_memory TEXT, event TEXT, created_at TEXT, updated_at TEXT, is_deleted INTEGER)")
        for i, (mid, ev, deleted) in enumerate(ops):
            con.execute("INSERT INTO history VALUES (?,?,?,?,?,?,?,?)",
                        ("h%d" % i, mid, None, "text-" + ev, ev, "2026-01-01T00:00:00",
                         "2026-01-02T00:00:00", 1 if deleted else 0))
        con.commit()
        con.close()

    def test_revived_id_excluded_via_any_row_delete(self):
        revived, normal = tmp_id(), tmp_id()
        with TempDir() as root:
            db = root / "mem0.db"
            self._make_history(str(db), [
                (normal, "ADD", 0),
                (revived, "ADD", 0), (revived, "DELETE", 1), (revived, "ADD", 0),
            ])
            with mock.patch.object(dc, "DB", str(db)), \
                    mock.patch.object(dc, "QDRANT_DB", str(root / "no-qdrant.sqlite")), \
                    mock.patch.object(dc, "LEDGER_DB", str(root / "no-ledger.db")):
                ids = {x["id"] for x in dc.read_mem0()}
            self.assertIn(normal, ids)
            self.assertNotIn(revived, ids, "末行为 ADD 的复活痕迹必须仍被剔除")


class BridgeHealthMeasurabilityTests(unittest.TestCase):
    """二次复验 #3：运行态表缺失 = 不可测，不得吞成 0 再判健康。"""

    def test_missing_runtime_tables_report_unmeasurable_not_zero(self):
        import sqlite3
        with TempDir() as root:
            ledger = root / "ledger.db"
            con = sqlite3.connect(str(ledger))
            con.execute("CREATE TABLE tombstones(memory_id TEXT PRIMARY KEY, source TEXT, reason TEXT, ts TEXT)")
            con.execute("CREATE TABLE memory_ledger(memory_id TEXT PRIMARY KEY, status TEXT, data TEXT, user_id TEXT, ts TEXT)")
            con.commit()
            con.close()
            patch_health = mock.patch.object(dc, "bridge_health", return_value={
                "bridge_code": "ok", "tombstones": 0, "live_points": 0, "ghosts": [],
                "last_heal": None, "last_reconcile": None,
                "conflicts": None, "failed_deletes": None, "orphan_pending": None})
            with mock.patch.object(dc, "LEDGER_DB", str(ledger)), \
                    mock.patch.object(dc, "_qdrant_records", return_value=[]), \
                    mock.patch.object(dc, "mem0_available", return_value=True), \
                    patch_health:
                health = dc.bridge_health()
                self.assertIsNone(health["conflicts"])
                self.assertIsNone(health["failed_deletes"])
                self.assertIsNone(health["orphan_pending"])
                result = dc._check_bridge_ledger()
                self.assertFalse(result["required_ok"])
                self.assertIn("不得视为零", result["detail"])


def _load_bridge():
    stub_pkg = types.ModuleType("mcp")
    stub_server = types.ModuleType("mcp.server")
    stub_mcpserver = types.ModuleType("mcp.server.mcpserver")

    class _MCPServer:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            return lambda fn: fn

        def run(self, *a, **k):
            pass

    stub_mcpserver.MCPServer = _MCPServer
    saved = {name: sys.modules.get(name) for name in ("mcp", "mcp.server", "mcp.server.mcpserver")}
    sys.modules["mcp"] = stub_pkg
    sys.modules["mcp.server"] = stub_server
    sys.modules["mcp.server.mcpserver"] = stub_mcpserver
    try:
        spec = importlib.util.spec_from_file_location("mcp_server_under_test", BRIDGE_SRC)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for name, old in saved.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


class BridgePendingReconcileTests(unittest.TestCase):
    """二次复验 #2 + 三轮复验 P1：孤儿判定需同时避开「本进程在飞」与「TTL 窗口内的他进程在飞」。"""

    def setUp(self):
        if not Path(BRIDGE_SRC).is_file():
            self.skipTest("桥源文件不存在")
        self.bridge = _load_bridge()

    def test_pending_never_confirmed_never_healed(self):
        b = self.bridge
        mid = tmp_id()
        with TempDir() as root:
            with mock.patch.object(b, "LEDGER_PATH", str(root / "ledger.db")):
                con = b._ledger()
                b._tombstone(mid, "mcp-delete-pending", "执行中", con=con)
                con.commit()
                con.close()
                self.assertNotIn(mid, b._confirmed_dead())

    def test_orphan_pending_promoted_or_revoked(self):
        b = self.bridge
        ok_id, no_rec_id = tmp_id(), tmp_id()
        with TempDir() as root:
            with mock.patch.object(b, "LEDGER_PATH", str(root / "ledger.db")):
                con = b._ledger()
                b._tombstone(ok_id, "mcp-delete-pending", "执行中", con=con)
                b._tombstone(no_rec_id, "mcp-delete-pending", "执行中", con=con)
                con.execute("INSERT INTO delete_attempts VALUES(?,?,?,?)", (ok_id, 1, None, "t"))
                promoted, revoked = b._reconcile_pending(con, now=time.time() + 999)
                con.commit()
                con.close()
                self.assertEqual((1, 1), (promoted, revoked))
                confirmed = b._confirmed_dead()
                self.assertIn(ok_id, confirmed, "有成功记录 → 转正")
                self.assertNotIn(no_rec_id, confirmed, "无记录 → 撤销墓碑，条目恢复可见")

    def test_inflight_and_ttl_window_pending_survive_reconcile(self):
        """三轮复验 P1：在飞集合与 TTL 窗口内的 pending 一律不动。"""
        b = self.bridge
        inflight_id, fresh_id = tmp_id(), tmp_id()
        with TempDir() as root:
            with mock.patch.object(b, "LEDGER_PATH", str(root / "ledger.db")):
                con = b._ledger()
                b._tombstone(inflight_id, "mcp-delete-pending", "本进程在飞", con=con)
                b._tombstone(fresh_id, "mcp-delete-pending", "他进程新鲜", con=con)
                promoted, revoked = b._reconcile_pending(con, inflight={inflight_id})
                con.commit()
                con.close()
                self.assertEqual((0, 0), (promoted, revoked), "在飞/TTL 内不得对账")
                tombs = b._tombstone_map() if hasattr(b, "_tombstone_map") else {}
                self.assertEqual(2, len(tombs))


class _FakeMemory:
    """最小 mem0 替身：够 delete/heal/list 路径跑通。"""

    def __init__(self, entries=None):
        self.entries = {e["id"]: dict(e) for e in (entries or [])}
        self.fail_delete = False

    def get_all(self, filters=None, top_k=1000):
        return {"results": [dict(x) for x in self.entries.values()]}

    def delete(self, memory_id=None):
        if self.fail_delete:
            raise RuntimeError("simulated backend failure")
        if memory_id not in self.entries:
            raise RuntimeError("Memory with id %s not found" % memory_id)
        del self.entries[memory_id]


class DeleteMemoryEndToEndTests(unittest.TestCase):
    """三轮复验 P0 防线：delete_memory 主路径端到端必须留/不留墓碑。"""

    def setUp(self):
        if not Path(BRIDGE_SRC).is_file():
            self.skipTest("桥源文件不存在")
        self.bridge = _load_bridge()

    def _run_delete(self, root, mid, fail=False):
        b = self.bridge
        fake = _FakeMemory([{"id": mid, "memory": "text", "user_id": b.DEFAULT_USER}])
        fake.fail_delete = fail
        with mock.patch.object(b, "LEDGER_PATH", str(root / "ledger.db")), \
                mock.patch.object(b, "_memory", fake):
            result = b.delete_memory(mid, b.DEFAULT_USER)
            con = b._ledger()
            try:
                tombs = {r[0]: r[1] for r in con.execute("SELECT memory_id, source FROM tombstones")}
                attempts = con.execute("SELECT memory_id, ok FROM delete_attempts").fetchall()
            finally:
                con.close()
            confirmed = b._confirmed_dead()
        return result, tombs, attempts, fake, confirmed

    def test_success_path_leaves_confirmed_tombstone(self):
        mid = tmp_id()
        with TempDir() as root:
            result, tombs, attempts, fake, confirmed = self._run_delete(root, mid)
            self.assertIn("已删除", result)
            self.assertNotIn(mid, fake.entries, "向量已删")
            self.assertEqual({mid: "mcp-delete"}, tombs,
                             "成功删除必须留下已确认墓碑（P0 防线）")
            self.assertIn(mid, confirmed)
            self.assertEqual([(mid, 1)], attempts)

    def test_failure_path_has_no_tombstone(self):
        mid = tmp_id()
        with TempDir() as root:
            result, tombs, attempts, fake, _ = self._run_delete(root, mid, fail=True)
            self.assertIn("删除失败", result)
            self.assertIn(mid, fake.entries, "失败删除不得把条目从向量里弄丢")
            self.assertEqual({}, tombs, "失败不得留下墓碑")
            self.assertEqual([(mid, 0)], attempts)


if __name__ == "__main__":
    unittest.main()
