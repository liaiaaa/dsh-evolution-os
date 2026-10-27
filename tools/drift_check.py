# -*- coding: utf-8 -*-
"""漂移检测器：只读审计 mem0 history、权威源、Inbox 与治理规则。
（只读=不改 mem0/Inbox/规则；报告写入 _reports 属正常产出，--quiet 连报告也不写。）"""
import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
from datetime import datetime

# —— 路径解析（2026-10-17 Linux 迁移适配）——
# 原实现硬编码 Windows 路径（E:\software\...），迁移到 Ubuntu 后全部失效，
# 导致 drift_check / weekly_audit 无法运行、.pending-alert.md 停在 2026-10-07 快照。
# 现改为：优先按脚本自身位置推导 BASE（仓库根 = tools/ 的上一级），
# 全部路径允许用环境变量覆盖；mem0 数据目录可缺失（纯文件大脑模式下属预期状态）。
_HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("DSH_EVOLUTION_OS_BASE") or os.path.dirname(_HERE)
KNOW = os.path.join(BASE, "knowledge")

# mem0 数据根：默认沿用历史位置，但允许 DSH_MEM0_DATA 覆盖。
# Linux 侧当前**未恢复** mem0，默认路径不存在时由各读取函数优雅降级为「未接入」。
MEM0_DATA = os.environ.get("DSH_MEM0_DATA") or os.path.expanduser("~/.dsh/mem0-data")
DB = os.path.join(MEM0_DATA, "mem0.db")
LEDGER_DB = os.path.join(MEM0_DATA, "mem0_ledger.db")
QDRANT_DB = os.path.join(MEM0_DATA, "qdrant", "collection", "mem0", "storage.sqlite")
BRIDGE_PY = os.path.join(MEM0_DATA, "mcp_server.py")

PROFILE = os.path.join(KNOW, "00-Profile", "个人偏好.md")
PROTOCOL = os.path.join(KNOW, "00-Profile", "个人AI协议.md")
INBOX = os.path.join(KNOW, "Inbox")
REPORT_DIR = os.path.join(INBOX, "_reports")


def mem0_available():
    """mem0 数据是否就位。False 表示当前为「纯文件大脑」模式，属预期状态而非故障。"""
    return os.path.isfile(DB)
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
    # 2026-09-27 用户逐条确认「保留原句」的 11 条（限定词为技术必然，非失真）
    "each stage must be confirmed as completed",
    "user must restart the dsh application after modifying plugins",
    "user must manually re-run",
    "must explicitly invoke plugin_manager",
    "bundle only updates its on-disk declaration",
    "activation is confirmed only when list_plugins",
    "must contain only pure ascii characters",
    "must retain the billing header",
    "and therefore never activated",
    "user must restart the application",
    "they only need to change web.config",
    "never forwarding internal urls",
    "are always sent to api.anysearch.com",
    "must avoid searching for internal urls",
    "cannot legally reproduce this flow",
]

# 仅作“疑似已确认偏好”的保守提示；未命中者不得自动归为 A 级。
# 白名单唯一权威源 = knowledge\00-Profile\已裁决保留注册表.md（含内容指纹）。
# 收紧（2026-10-01 二次复验 #1）：注册表缺失/解析为空 → 返回 None，**豁免全部停用**
# （宁可 C 组重新上报，也不允许「文件丢=永久免检」的静默降级）；无指纹行同样不豁免。
# 下方元组仅为历史参照（09-27 批次1 + 限定词 11 条的 id 清单），**不参与任何豁免判定**。
KEEP_REGISTRY_FILE = os.path.join(KNOW, "00-Profile", "已裁决保留注册表.md")
USER_CONFIRMED_KEEP = (
    "0f2966a1-7b7d-41ff-98b0-d167a06c6e45",  # 改插件必须重启 DSH
    "bdbafa02-c5ec-4165-b96d-15e4b09cc2d4",  # bundle 必须 set_bundle
    "2a4ec0db-6889-4833-9968-44b24242a1ea",  # 分阶段执行协议（09-27 裁决保留）
    "1512dddb-9d24-433a-b5c6-48ea594f7476",  # 计费头必须保留
    "58851dae-eed6-4b6c-aa7d-c6772f4a8a25",  # Zcode 配额验证码不可绕
    "73667f0d-34ad-488b-955c-2c3427dd1796",  # dsh-quiet 不加载决定
    "a6e9025a-3456-4d06-8d5c-d147e8a3eb1b",  # anysearch 激活需重启
    "9fcd5b5b-13c7-4151-b8d5-2f0a0d9d1283",  # 内网保护实现（never）
    "8cfd0c1a-3e4c-491a-96b4-0a668e4e7bfd",  # 安全残留面（always/must 属实）
    "2597bb36-a833-4ebb-a2f4-ee929dd57a51",  # 批次1 两阶段流程
    "af077a53-5224-474b-8874-71f4368bd0fa",  # 批次1 自动化偏好
    "f00ace2e-eb2a-4977-9374-bde09f4a31ae",  # 批次1 精确路径
    "4f49d6a0-af9a-4824-9ce4-41566781432b",  # 批次1 大脑分工
    "f708376a-1691-4ccf-afa0-2c95bc49d383",  # 批次1 临时文件清理
    "9c8bcf73-b144-4ec3-ac8c-5a992ecb1972",  # 批次1 dsh-quiet 仅美学
    "0b5e9e79-02c4-422a-ad15-7354ec6e3186",  # 点击式选项裁决偏好（09-27 用户批准沉淀并已补 个人偏好.md，git 244df7e；白名单当日承诺漏落，09-30 补记）
)


def _fp12(text):
    """指纹＝原文逐字节哈希（不做 Unicode 归一化，2026-10-01 二次复验 #9 决议）：
    mem0 对文本的任何空白/破折号级改写也应显式曝光复核，宁误报不漏检。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def load_registry():
    """解析注册表 md → {id: 指纹}；文件缺失/解析不出任何行 → 返回 None（豁免整体停用）。
    2026-10-01（独立审计 #1/#2/#3 + 二次复验 #1）：白名单唯一权威源 = 注册表；
    豁免只覆盖裁决时的原文（指纹相符）；指纹缺失/不符 → 不豁免，重新上报。"""
    try:
        with open(KEEP_REGISTRY_FILE, "r", encoding="utf-8") as stream:
            body = stream.read()
    except OSError:
        return None
    registry = {}
    for line in body.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2 or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", cells[0].strip("`")):
            continue
        registry[cells[0].strip("`")] = cells[1].strip("`")
    return registry or None


def read_registry():
    """注册表 id 集合；注册表不可用时为空集（classify 因此不会豁免任何条目）。"""
    reg = load_registry()
    return set() if reg is None else set(reg)


def registry_missing():
    """供义务检查/告警使用：注册表不可读时返回 True（此时白名单豁免已整体停用）。"""
    return load_registry() is None


def registry_exempt(mid, text):
    """仅当注册表存在、id 在册、且指纹与当前原文逐字节相符时才豁免。
    None 指纹（新裁决未登记/登记残缺）与文件缺失一样：不豁免。"""
    reg = load_registry()
    if reg is None:
        return False
    fp = reg.get(mid)
    if not fp:
        return False
    return fp == _fp12(text)


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
    # 2026-09-27 批次1 用户确认的 A 级偏好（消除每周「未知」误报）
    "two-phase collaboration workflow", "automation of repetitive manual steps",
    "specific, exact file paths", "cognitive division of labor",
    "all temporary files generated during task execution",
    "considers dsh-quiet purely aesthetic",
    # 2026-09-27 用户裁决「限定词保留原句」的技术事实条目（防每周重复误报）
    "restart the dsh application after modifying plugins",
    "invoke plugin_manager's set_bundle",
    "retain the billing header",
    "daily token quota is enforced",
    "not to load the dsh-quiet plugin",
    "change web.config.searchprovider back",
    "islocaltarget() detects localhost",
    "security residual surface",
    "cmd.exe reads .bat files using gbk encoding",
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
    "DSH mem0-memory Skill": os.path.expanduser("~/.dsh/skills/mem0-memory/SKILL.md"),
    "WorkBuddy MEMORY.md": os.path.expanduser("~/.workbuddy/MEMORY.md"),
    "MiMO 全局 AGENTS.md": os.path.expanduser("~/.config/mimocode/AGENTS.md"),
    "MiMO 项目 AGENTS.md": os.path.join(BASE, "AGENTS.md"),
}

# 注：本字典为历史遗留，实际检查走 CONTRACT_CHECKS（2026-10-24 确认无引用）
OBLIGATION_NEEDLES = {
    # 2026-10-22 规则由「必须询问沉淀」改为「分级自动沉淀」，检查谓词同步更新
    "项目 AGENTS.md": ("分级自动沉淀", "A 级"),
    "个人AI协议.md": ("分级自动沉淀", "破坏性操作红线"),
    "个人偏好.md": ("任务收尾的分级沉淀", "拿不准"),
    "DSH mem0-memory Skill": ("任务收尾的沉淀询问", "不得自行 `delete_memory`"),
    "WorkBuddy MEMORY.md": ("任务收尾必须询问沉淀", "不自行删除或覆盖"),
    "MiMO 全局 AGENTS.md": ("任务收尾的沉淀询问", "不得自行删除或覆盖"),
    "MiMO 项目 AGENTS.md": ("分级自动沉淀", "A 级"),
}

# 每个适用文件的治理合同检查：needles 为 (说明, 必需包含, 不得包含)。
# 否定句/历史说明若只以否定形式出现，会因“必需包含”缺失或“不得包含”命中而失败。
NEGATION_MARKERS = ("原表述", "曾经的假设", "早期假设", "已废止", "旧规则", "历史说明", "不再")

CONTRACT_CHECKS = {
    "项目 AGENTS.md": [
        ("Obsidian 权威优先级", ("个人偏好.md", "终极权威"), ()),
        ("A 级必须问用户", ("A 级", "必须问用户"), ()),
        ("B 级直接写入正式目录", ("B 级", "直接写入"), ()),
        ("C 级禁止写入", ("C 级", "禁止"), ()),
        ("不得自行删除或覆盖", ("不得自行删除或覆盖",), ()),
        ("任务收尾分级沉淀", ("分级自动沉淀",), ()),
        ("判级卡两条硬规则", ("拿不准", "升 A"), ()),
        ("会话开始主动报告待决事项", (".pending-alert.md",), ()),
    ],
    "个人AI协议.md": [
        ("Obsidian 权威优先级", ("权威源",), ()),
        ("A 级必须问用户", ("A 级", "必须问用户"), ()),
        ("B 级直接写入正式目录", ("B 级", "直接写"), ()),
        ("C 级禁止写入", ("C 级", "禁止"), ()),
        ("不得自行删除或覆盖", ("不得自行删除或覆盖",), ()),
        ("收尾分级沉淀", ("分级沉淀",), ()),
        ("判级卡两条硬规则", ("拿不准", "升 A"), ()),
        ("破坏性操作红线", ("破坏性操作红线",), ()),
        ("豆包不接入共享 mem0", ("豆包不接入共享 mem0",), ()),
    ],
    "个人偏好.md": [
        ("mem0 与权威源关系", ("个人偏好的权威版本",), ()),
        ("收尾分级沉淀", ("分级沉淀",), ()),
        ("破坏性操作红线已迁出", ("破坏性操作红线",), ()),
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
        ("A 级必须问用户", ("A 级", "必须问用户"), ()),
        ("C 级禁止写入", ("C 级", "禁止"), ()),
        ("不得自行删除或覆盖", ("不得自行删除或覆盖",), ()),
        ("收尾分级沉淀", ("分级自动沉淀",), ()),
    ],
}

DOUBAO_RECORD_REQUIRED = (
    "schema_version", "verified_at", "outcome", "scenario",
    "doubao_reply_evidence", "expected_authority", "observed_conclusion", "confirmed_by",
)
DOUBAO_RECORD_SCHEMA_VERSION = 1
DOUBAO_VERIFICATION_INTERVAL_DAYS = 90


class _Stub:
    """占位对象：用于在没有 qdrant_client 的环境里反序列化 Qdrant 点。

    pickle 里引用了 `qdrant_client.http.models.models.PointStruct` 等类。
    未安装该包时 pickle.loads 会抛 ModuleNotFoundError，导致**全部点被静默跳过**、
    误报「实时向量点数 0」——2026-10-17 在 Linux 上实测到该静默失败。
    这里用一个不依赖第三方包的 Unpickler，把未知类映射为可承载属性的占位对象。
    """

    def __init__(self, *args, **kwargs):
        self._args = args

    def __setstate__(self, state):
        if isinstance(state, dict):
            self.__dict__.update(state)
        elif isinstance(state, tuple) and len(state) == 2 and isinstance(state[0], dict):
            self.__dict__.update(state[0])
        else:
            self.__dict__["_state"] = state

    def __repr__(self):
        return "<Stub %s>" % type(self).__name__


class _LenientUnpickler(__import__("pickle").Unpickler):
    """未知模块/类一律降级为 _Stub，不中断整批读取。"""

    _MODEL_CACHE = {}

    def find_class(self, module, name):
        try:
            return super().find_class(module, name)
        except (ImportError, AttributeError):
            key = (module, name)
            stub = self._MODEL_CACHE.get(key)
            if stub is None:
                stub = type(name, (_Stub,), {})
                self._MODEL_CACHE[key] = stub
            return stub


def _lenient_loads(blob):
    import io
    import pickle
    try:
        return pickle.loads(blob)
    except (ImportError, AttributeError, ModuleNotFoundError):
        return _LenientUnpickler(io.BytesIO(blob)).load()


def _qdrant_payload(blob):
    """取 Qdrant 点的 payload。

    实测结构（2026-10-17）：pickle 出来是 pydantic 模型，真实字段在
    `__dict__['__dict__']` 里（外层是 pydantic 的槽位，内层才是字段），
    所以这里逐层探测，而不是只看顶层属性。
    """
    ps = _lenient_loads(blob)
    candidates = []
    # 1) 顶层属性
    candidates.append(getattr(ps, "payload", None))
    # 2) 顶层 __dict__
    top = getattr(ps, "__dict__", None)
    if isinstance(top, dict):
        candidates.append(top.get("payload"))
        # 3) pydantic 嵌套：__dict__['__dict__']['payload']
        inner = top.get("__dict__")
        if isinstance(inner, dict):
            candidates.append(inner.get("payload"))
    for pl in candidates:
        if pl is None:
            continue
        try:
            return pl if isinstance(pl, dict) else dict(pl)
        except (TypeError, ValueError):
            continue
    return None


def _qdrant_records():
    """直读 Qdrant 本地存储：返回 [(id, data, created_at)]（仅 dsh-user）；不可读返回 None。"""
    if not os.path.isfile(QDRANT_DB):
        return None
    try:
        con = sqlite3.connect("file:%s?mode=ro" % QDRANT_DB.replace("\\", "/"), uri=True)
        rows = con.execute("SELECT id, point FROM points").fetchall()
        con.close()
    except sqlite3.Error:
        return None
    out = []
    for pid_raw, blob in rows:
        try:
            mid = str(_lenient_loads(base64.b64decode(pid_raw)))
            pl = _qdrant_payload(blob)
        except Exception:
            continue
        if not pl or str(pl.get("user_id") or "") != "dsh-user":
            continue
        out.append((mid, pl.get("data") or "", str(pl.get("created_at") or "")))
    return out


def read_qdrant_records(user_id=None):
    """公共接口（weekly_audit 使用）：直读向量点集；不可读返回 None。user_id 参数保留兼容，当前集合仅 dsh-user。"""
    return _qdrant_records()


def read_ledger_tombstones():
    """权威账本：已批准删除的记忆 id 集合（tombstone）。不存在则空集。"""
    if not os.path.isfile(LEDGER_DB):
        return set()
    try:
        con = sqlite3.connect("file:%s?mode=ro" % LEDGER_DB.replace("\\", "/"), uri=True)
        ids = {r[0] for r in con.execute("SELECT memory_id FROM tombstones")}
        con.close()
        return ids
    except sqlite3.Error:
        return set()


def _bridge_scheme_state():
    """mcp_server.py 是否已接权威账本（方案A）。"""
    try:
        with open(BRIDGE_PY, "r", encoding="utf-8") as stream:
            head = stream.read(4096)
    except OSError:
        return "missing"
    return "ok" if "mem0_ledger" in head else "old"


def read_mem0():
    """权威活跃集合 = Qdrant 实时点 −（墓碑 ∪ history 任意行已删）；
    向量不可读时回退 history 终态重建（仍应用上述删除集）。2026-10-01 二次复验 #4/#7 修正。
    2026-10-17：mem0 数据缺失（Linux 纯文件大脑模式）时返回空列表，不抛异常。"""
    if not mem0_available():
        return []
    con = sqlite3.connect("file:%s?mode=ro" % DB.replace("\\", "/"), uri=True)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("""
        SELECT id, memory_id, old_memory, new_memory, event,
               created_at, updated_at, is_deleted
        FROM history ORDER BY created_at ASC, rowid ASC
    """)
    latest, order = {}, []
    deleted_ids = set()  # 二次复验 #4：必须扫**任意行**——latest 覆盖式收集会让 ADD→DELETE→ADD 的复活痕迹被末行掩盖
    for row in cur.fetchall():
        mid = row["memory_id"]
        if mid not in latest:
            order.append(mid)
        if row["event"] == "DELETE" or row["is_deleted"]:
            deleted_ids.add(mid)
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
    # ——权威活跃集合 = Qdrant 实时点 − tombstone 账本（2026-09-27 建立，2026-10-01 修正注释）——
    # 事实修正（审计 #9，mem0ai 2.0.20 复核）：delete() 其实**会**写 history DELETE 事件，
    # 但 DELETE 行的 created_at 沿用原 ADD、真实时刻在 updated_at——旧注释「delete 不写
    # history」源于按 created_at 分组的探针误读，作废。
    # 账本仍是事实源的原因与之不同：多进程共享内嵌 Qdrant「内存快照+整体落盘」互相
    # 覆盖，已批准删除的条目会被别的桥进程写回复活；history 与向量集合因此会分叉，
    # 以「向量点 − (墓碑 ∪ history已删)」为准并另报幽灵数（审计 #17：账本建立前的
    # 旧删除只有 history 证据，交叉核验防止其借向量残留复活）。
    tomb = read_ledger_tombstones() | deleted_ids
    records = _qdrant_records()
    if records is None:
        if tomb:
            out = [x for x in out if x["id"] not in tomb]
        return out
    hist = {x["id"]: x for x in out}
    merged = []
    for mid, text, created in records:
        if mid in tomb:
            continue
        hrow = hist.get(mid)
        merged.append({
            "id": mid,
            "memory": text or (hrow["memory"] if hrow else ""),
            "created_at": created or (hrow["created_at"] if hrow else ""),
            "updated_at": created or (hrow["updated_at"] if hrow else ""),
        })
    merged.sort(key=lambda x: x["created_at"])
    return merged


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

        # 1.5) 注册表白名单（用户逐项裁决保留）：仅在内容指纹一致时豁免。
        #      指纹不符 = 条目自裁决后被改写 → 重新上报，不永久免检（审计 #1/#2）。
        #      C 级/身份检查在其之前，白名单无法为凭据类内容开脱。
        reg = read_registry()
        if item.get("id") in reg:
            if registry_exempt(item.get("id"), text):
                keep.append(item)
                continue
            place(item, "需人工分类", "注册表条目内容已变（指纹不符），需用户重新裁决")
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


def _check_bridge_ledger():
    """桥运行态 = bridge_health() 汇总（幽灵/复活企图/失败删除全部纳入，审计 #7/#13）。
    2026-10-17：mem0 未接入时返回 not_applicable——纯文件大脑模式下属预期状态，
    不应计为「规则缺失」，否则每次体检都报一批假警报。"""
    if not mem0_available():
        return {"status": "not_applicable", "required_ok": True,
                "detail": "mem0 未接入（纯文件大脑模式），本项不适用；恢复 mem0 后自动重新生效",
                "path": BRIDGE_PY}
    health = bridge_health()
    bridge_db = LEDGER_DB
    if health["bridge_code"] != "ok":
        return {"status": "missing_rule", "required_ok": False,
                "detail": "mcp_server.py 为旧版（无权威账本）——需重启使用 mem0 的会话生效"
                          if health["bridge_code"] == "old" else "mcp_server.py 缺失",
                "path": BRIDGE_PY}
    if not os.path.isfile(bridge_db):
        return {"status": "missing_rule", "required_ok": False,
                "detail": "mem0_ledger.db 不存在", "path": bridge_db}
    if health["live_points"] is None:
        return {"status": "unreadable", "required_ok": False,
                "detail": "账本或向量集合不可读（读过滤依赖账本，必须可读）", "path": bridge_db}
    ghosts = len(health["ghosts"])
    unmeasurable = [k for k in ("conflicts", "failed_deletes", "orphan_pending") if health[k] is None]
    status_ok = (ghosts == 0 and not unmeasurable
                 and health["conflicts"] == 0 and health["failed_deletes"] == 0
                 and health["orphan_pending"] == 0)
    detail = ("桥已接账本；墓碑 %d / 幽灵 %d（>0 将于下次桥重启自愈）/ 复活企图 %s / 删除失败 %s / 孤儿pending %s"
              % (health["tombstones"], ghosts,
                 "?" if health["conflicts"] is None else health["conflicts"],
                 "?" if health["failed_deletes"] is None else health["failed_deletes"],
                 "?" if health["orphan_pending"] is None else health["orphan_pending"]))
    if unmeasurable:
        detail += "（运行态表未建/不可读：%s——桥首次写入后自动补齐，此前不得视为零）" % "、".join(unmeasurable)
    if health["last_heal"] is not None:
        detail += "；最近自愈：%s" % health["last_heal"]
    if health.get("last_reconcile") is not None:
        detail += "；最近对账：%s" % health["last_reconcile"]
    return {"status": "ok" if status_ok else "missing_rule", "required_ok": status_ok,
            "detail": detail,
            "path": bridge_db}


def bridge_health():
    """方案A 运行态体检（供 weekly_audit 主路径使用；全只读）。
    二次复验 #2/#3：表缺失 → 计数为 None（「不可测」），绝不吞成 0；
    孤儿 pending 墓碑（崩溃残留）单独暴露，由桥启动对账清理。"""
    tomb = read_ledger_tombstones()
    records = _qdrant_records()
    live = {r[0] for r in records} if records is not None else set()
    heal = None
    reconcile = None
    conflicts = failures = pending = None
    try:
        con = sqlite3.connect("file:%s?mode=ro" % LEDGER_DB.replace("\\", "/"), uri=True)
        row = con.execute("SELECT data FROM memory_ledger WHERE memory_id='_last_heal'").fetchone()
        heal = row[0] if row else None
        row = con.execute("SELECT data FROM memory_ledger WHERE memory_id='_last_reconcile'").fetchone()
        reconcile = row[0] if row else None
        try:
            conflicts = con.execute("SELECT count(*) FROM ledger_conflicts").fetchone()[0]
        except sqlite3.Error:
            conflicts = None
        try:
            failures = con.execute("SELECT count(*) FROM delete_attempts WHERE ok=0").fetchone()[0]
            # 三轮复验 P3：孤儿 pending 判定与桥侧 _reconcile_pending 同口径——
            # 需超 TTL 窗口（120s）且无成功记录，新鲜 pending（他进程在飞）不算孤儿。
            pending = con.execute(
                "SELECT count(*) FROM tombstones t WHERE t.source='mcp-delete-pending' "
                "AND (t.ts IS NULL OR t.ts = '' OR "
                "     julianday(replace(t.ts, 'T', ' ')) < julianday('now', 'localtime', '-120 seconds')) "
                "AND NOT EXISTS (SELECT 1 FROM delete_attempts a WHERE a.memory_id = t.memory_id AND a.ok = 1)"
            ).fetchone()[0]
        except sqlite3.Error:
            failures = None
            pending = None
        con.close()
    except sqlite3.Error:
        pass
    return {
        "bridge_code": _bridge_scheme_state(),
        "tombstones": len(tomb),
        "live_points": len(records) if records is not None else None,
        "ghosts": sorted(live & tomb),
        "last_heal": heal,
        "last_reconcile": reconcile,
        "conflicts": conflicts,
        "failed_deletes": failures,
        "orphan_pending": pending,
    }


def check_obligations(paths=None):
    """读取每个真实规则文件，检查关键治理合同在位情况（静态证据，不等于行为合规）。
    2026-10-17：其他 Agent（WorkBuddy/MiMO/mem0 skill）的规则文件缺失时标记
    not_applicable 而非 missing——Linux 侧这些 Agent 尚未接入，属预期状态。"""
    paths = DEFAULT_OBLIGATION_PATHS if paths is None else paths
    # 这些规则文件的缺失属「该 Agent 未接入本机」，不是治理故障
    OPTIONAL_AGENT_RULES = {
        "DSH mem0-memory Skill", "WorkBuddy MEMORY.md", "MiMO 全局 AGENTS.md",
    }
    results = {}
    for label, path in paths.items():
        path = os.fspath(path)
        if not os.path.isfile(path):
            if label in OPTIONAL_AGENT_RULES:
                results[label] = {
                    "status": "not_applicable", "required_ok": True,
                    "detail": "该 Agent 未接入本机（Linux 侧未迁移），本项不适用",
                    "path": path,
                }
            else:
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
    results["mem0 桥方案A账本"] = _check_bridge_ledger()
    results["已裁决保留注册表"] = _check_keep_registry()
    return results


def _check_keep_registry():
    """注册表是白名单唯一权威源（二次复验 #1）：不可读时豁免已整体停用，
    必须显式报告——宁可 C 组重新上报，也绝不静默放行。"""
    if registry_missing():
        return {"status": "missing_rule", "required_ok": False,
                "detail": "注册表缺失/解析为空 → 指纹豁免层已整体停用；其余条目暂靠 KEEP_HINTS 保守提示兜底"
                          "（覆盖面更窄，C/越界组可能出现重报，属预期保护）",
                "path": KEEP_REGISTRY_FILE}
    n = len(load_registry())
    # 护栏（非常规保护路径，三轮复验 P3 注记）：兜底清单只在不豁免路径作参照，
    # 若有人只加兜底不加注册表，此处显式提醒同步；真正保护来自 registry_missing 分支。
    legacy_only = [mid for mid in USER_CONFIRMED_KEEP if mid not in load_registry()]
    detail = "注册表在位（%d 条含指纹）" % n
    if legacy_only:
        detail += "；兜底清单中 %d 条未入表：%s" % (len(legacy_only), ", ".join(m[:8] for m in legacy_only))
    return {"status": "ok" if not legacy_only else "missing_rule", "required_ok": not legacy_only,
            "detail": detail, "path": KEEP_REGISTRY_FILE}


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
    # 2026-10-27：Windows 盘符路径在 POSIX 上不能走 abspath（会被拼上 cwd，
    # 导致 %USERPROFILE% 前缀失效、真实用户名反而暴露在更长的路径里）。
    raw = str(path)
    shown = raw if re.match(r"(?i)^[A-Z]:[\\/]", raw) else os.path.abspath(raw)
    shown = re.sub(r"(?i)\b[A-Z]:\\Users\\[^\\]+", "%USERPROFILE%", shown)
    return shown


def _rule_status_text(result):
    return {
        "ok": "OK",
        "manual": "需人工验证",
        "missing": "文件缺失",
        "missing_rule": "规则缺失",
        "conflict": "规则冲突",
        "unreadable": "无法读取",
        "not_applicable": "不适用（该组件未接入）",
    }.get(result.get("status"), "未知")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass
    quiet = "--quiet" in sys.argv
    memories = read_mem0()
    tomb = read_ledger_tombstones()
    records = _qdrant_records()
    live_count = len(records) if records is not None else None
    ghosts = sorted({r[0] for r in records} & tomb) if records is not None else []
    buckets, keep = classify(memories)
    _, profile_ids = read_profile()
    memory_ids = {item["id"] for item in memories}
    unreferenced = sorted(memory_ids - profile_ids)
    # mem0 未接入（纯文件大脑模式）时，权威源里的 mem0 UUID 引用无从校验，不算缺失
    explicit_missing = sorted(profile_ids - memory_ids) if mem0_available() else []
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
    add("| 权威活跃集合 | **%d** | Qdrant 实时点 − tombstone 账本（%s） |" % (
        len(memories), "直读成功" if live_count is not None else "直读失败，history 兜底"))
    add("| 磁盘残留待清（已批准删除仍在盘） | %d | mem0_ledger ∩ Qdrant；桥重启后自动 purge |" % len(ghosts))
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
    print("权威活跃集合(实时-账本): %d" % len(memories))
    print("磁盘残留待清/桥状态   : %d / %s" % (len(ghosts), _bridge_scheme_state()))
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
