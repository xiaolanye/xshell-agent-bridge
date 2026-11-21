# Xshell Agent Bridge - run this file from Xshell's Tools > Script > Run menu.
# Xshell 8 embeds Python 3.8 and injects the global `xsh` automation object.

import json
import os
import re
import time


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
CONFIG_PATH = os.environ.get(
    "XSHELL_BRIDGE_CONFIG",
    os.path.abspath(os.path.join(PROJECT_ROOT, "config", "local.json")),
)


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


CONFIG = load_config()
POLL_MS = int(CONFIG.get("bridge", {}).get("pollIntervalMs", 250))
# 屏幕抓取比心跳更贵（整屏 Get + JSON 序列化），单独限频，默认 1 秒一次。
SCREEN_INTERVAL_MS = int(CONFIG.get("bridge", {}).get("screenIntervalMs", 1000))
# 发送输入后短暂等待，让回显和首批输出落到屏幕上，再抓图回写状态。
SETTLE_MS = int(CONFIG.get("bridge", {}).get("settleAfterSendMs", 250))
# 命令结束后等提示符重新出现，确认输出已经落屏（0 表示关闭该行为）。
WAIT_PROMPT_MS = int(CONFIG.get("bridge", {}).get("waitForPromptMs", 3000))
PROMPT_POLL_MS = int(CONFIG.get("bridge", {}).get("promptPollMs", 120))
# 优雅停止：批处理写入该文件后，脚本自行退出，避免 Xshell 强杀脚本线程。
STOP_PATH = os.path.join(PROJECT_ROOT, "data", "stop-bridge")
# 只响应“启动之后”写入的停止信号，这样多个标签页的脚本都能同时退出，
# 且残留的旧信号不会阻止下一次启动。
STARTED_AT = time.time()
BRIDGE_ID = os.urandom(16).hex()
PROTOCOL = "xshell-agent-file-v2"
APPROVAL_MODE = "xshell-dialog-v1"
COMMAND_POLICY_MODE = "agent-destructive-block-v1"
SAFETY_MODES_PROTOCOL = "xshell-safety-modes-v1"
RISK_LABELS = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "严重",
}
IPC_ROOT = os.path.abspath(os.path.join(PROJECT_ROOT, "data", "ipc"))
DESKTOP_LAUNCH_ROOT = os.path.abspath(os.path.join(PROJECT_ROOT, "data", "desktop-launch"))
TRANSFER_ROOT = os.path.abspath(os.path.join(PROJECT_ROOT, "data", "transfers"))
DESKTOP_LAUNCH_PROTOCOL = "xshell-agent-desktop-launch-v1"
SESSION_DIR = os.path.join(IPC_ROOT, BRIDGE_ID)
STATE_PATH = os.path.join(SESSION_DIR, "state.json")
COMMAND_PATH = os.path.join(SESSION_DIR, "command.json")
ACTIVE_PATH = os.path.join(SESSION_DIR, "command.active.json")
RESULT_PATH = os.path.join(SESSION_DIR, "result.json")
LOOP_ERROR_PATH = os.path.join(SESSION_DIR, "bridge-error.json")
LAST_STATE = None
LAST_TOUCH_AT = 0.0
LAST_SCREEN = None
LAST_META = None
CACHED_SCREEN = None
CACHED_AT = 0.0
HARD_BLOCKED_INPUT_PATTERNS = (
    (
        "文件删除或内容清空",
        re.compile(
            r"(?:^|[\s;&|()'\"`])(?:/(?:usr/)?bin/)?"
            r"(?:rm|rmdir|unlink|shred|remove-item|clear-content|erase|del|rd)"
            r"(?=[\s;&|()'\"`]|$)",
            re.I,
        ),
    ),
    (
        "脚本删除文件",
        re.compile(
            r"\b(?:os\.(?:remove|unlink)|shutil\.rmtree|fileutils\.rm_rf|"
            r"fs\.(?:rm|unlink)(?:sync)?|[a-z_$][\w$]*\.unlink)\s*\(",
            re.I,
        ),
    ),
    (
        "find 批量删除",
        re.compile(r"\bfind\b[^\r\n]{0,2000}(?:-delete|-exec(?:dir)?\s+)", re.I),
    ),
    (
        "容器或编排资源删除",
        re.compile(
            r"\b(?:(?:docker|podman)\s+"
            r"(?:(?:container|image|volume|network|system|builder)\s+)?(?:rm|rmi|prune)|"
            r"(?:docker|podman)\s+compose\b[^\r\n;&|]{0,240}\bdown\b|"
            r"kubectl\s+delete|helm\s+uninstall|crictl\s+(?:rm|rmi))\b",
            re.I,
        ),
    ),
    (
        "数据库删除或清空",
        re.compile(
            r"(?:^|[\s;\"'`])(?:drop\s+(?:database|schema|table|view|index|user)|"
            r"truncate\s+(?:table\s+)?|delete\s+from)\b",
            re.I,
        ),
    ),
    (
        "磁盘格式化或擦除",
        re.compile(
            r"(?:^|[\s;&|()'\"`])"
            r"(?:mkfs(?:\.[\w-]+)?|wipefs|blkdiscard|fdisk|cfdisk|sfdisk|format-volume)"
            r"(?=[\s;&|()'\"`]|$)|\bdd\b[^\r\n]{0,500}\bof\s*=\s*/dev/",
            re.I,
        ),
    ),
    (
        "软件包卸载",
        re.compile(
            r"\b(?:(?:apt|apt-get)\b[^\r\n;&|]{0,240}\b(?:remove|purge|autoremove)|"
            r"(?:yum|dnf)\b[^\r\n;&|]{0,240}\b(?:remove|erase|autoremove)|"
            r"rpm\b[^\r\n;&|]{0,240}\s-e(?:\s|$)|apk\s+del|pacman\s+-R)\b",
            re.I,
        ),
    ),
    (
        "版本库强制清理",
        re.compile(
            r"\bgit\s+(?:reset\b[^\r\n;&|]{0,240}--hard|"
            r"clean\b[^\r\n;&|]{0,240}(?:-[^\s]*f|--force))\b",
            re.I,
        ),
    ),
    (
        "关机或重启",
        re.compile(
            r"(?:^|[\s;&|()'\"`])(?:shutdown|reboot|poweroff|halt)"
            r"(?=[\s;&|()'\"`]|$)|\bsystemctl\s+(?:poweroff|reboot|halt)\b|"
            r"(?:^|[\s;&|])init\s+[06](?=\s|$)",
            re.I,
        ),
    ),
    (
        "防火墙规则清空",
        re.compile(
            r"\biptables\b[^\r\n;&|]{0,240}(?:\s-F|\s-X|--flush)|"
            r"\bnft\s+flush\s+ruleset\b",
            re.I,
        ),
    ),
)
DYNAMIC_EXECUTION_PATTERNS = (
    (
        "将编码或下载内容交给命令解释器执行",
        re.compile(
            r"\b(?:base64|openssl\s+enc|xxd\s+-r|curl|wget)\b[^\r\n]{0,1000}"
            r"\|\s*(?:(?:sudo|env|command|nohup)\s+)*(?:/?(?:usr/)?bin/)?(?:ba)?sh\b",
            re.I,
        ),
    ),
    (
        "命令解释器或脚本解释器执行",
        re.compile(
            r"(?:^|[\r\n;&|]\s*)(?:(?:sudo|env|command|nohup|time|nice)\s+)*"
            r"(?:/?(?:usr/)?bin/)?(?:ba)?sh\b|"
            r"(?:^|[\r\n;&|]\s*)(?:(?:sudo|env|command|nohup|time|nice)\s+)*"
            r"(?:/?(?:usr/)?bin/)?(?:python(?:3)?|node|perl|ruby|php|lua|pwsh|powershell|cmd(?:\.exe)?)\b",
            re.I,
        ),
    ),
    (
        "动态变量或命令替换执行",
        re.compile(r"\$\(|`|(?:^|[\r\n;&|]\s*)(?:eval|source)\b|(?:^|[\r\n;&|]\s*)\.\s+", re.I),
    ),
)


def atomic_write_json(path, value):
    temporary = path + "." + os.urandom(4).hex() + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False)
        handle.flush()
    os.replace(temporary, path)


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def record_loop_error(stage, error):
    # A broad catch keeps the Xshell script alive, but it must never hide an
    # error that prevents an approval dialog from being shown. Keep the most
    # recent failure next to the IPC files so it can be inspected locally.
    try:
        atomic_write_json(
            LOOP_ERROR_PATH,
            {
                "stage": str(stage),
                "error": str(error),
                "updatedAt": time.time(),
            },
        )
    except Exception:
        pass


def safe_value(getter, default=None):
    try:
        return getter()
    except Exception:
        return default


def metadata():
    note_step("metadata")
    return {
        "connected": bool(safe_value(lambda: xsh.Session.Connected, False)),
        "remoteAddress": str(safe_value(lambda: xsh.Session.RemoteAddress, "")),
        "remotePort": int(safe_value(lambda: xsh.Session.RemotePort, 0) or 0),
        "sessionPath": str(safe_value(lambda: xsh.Session.Path, "")),
        "rows": int(safe_value(lambda: xsh.Screen.Rows, 0) or 0),
        "columns": int(safe_value(lambda: xsh.Screen.Columns, 0) or 0),
        "approvalMode": APPROVAL_MODE,
        "commandPolicyMode": COMMAND_POLICY_MODE,
        "safetyModesProtocol": SAFETY_MODES_PROTOCOL,
        "desktopLaunchMode": "xshell-startfile-v1",
    }


META_CACHE = {"value": None, "at": 0.0}
META_TTL_S = 3.0
# 空闲降频：连续 IDLE_AFTER_S 秒没有任务后，把轮询和抓屏都放慢，
# 尽量把"挂机时对 Xshell 原生接口的调用"压到接近零。
IDLE_AFTER_S = int(CONFIG.get("bridge", {}).get("idleAfterSeconds", 60))
IDLE_POLL_MS = int(CONFIG.get("bridge", {}).get("idlePollMs", 2000))
IDLE_SCREEN_MS = int(CONFIG.get("bridge", {}).get("idleScreenMs", 10000))
LAST_ACTIVITY_AT = time.monotonic()


def is_idle():
    return (time.monotonic() - LAST_ACTIVITY_AT) >= IDLE_AFTER_S


def cached_metadata(ttl_s=None):
    """元数据变化很慢，缓存几秒再读。

    空闲时这是循环里最重的部分：250ms 轮询意味着每秒 24 次原生属性访问
    （Connected / RemoteAddress / RemotePort / Path / Rows / Columns），
    挂机一整夜就是几十万次跨进程调用，是 Xshell 长时间运行后崩溃的
    主要嫌疑之一。缓存后降到每秒不到 1 次。
    """
    limit = META_TTL_S if ttl_s is None else ttl_s
    now = time.monotonic()
    if META_CACHE["value"] is None or now - META_CACHE["at"] >= limit:
        META_CACHE["value"] = metadata()
        META_CACHE["at"] = now
    return META_CACHE["value"]


def capture_screen():
    note_step("screen.get")
    rows = int(safe_value(lambda: xsh.Screen.Rows, 0) or 0)
    columns = int(safe_value(lambda: xsh.Screen.Columns, 0) or 0)
    if rows < 1 or columns < 1:
        return ""
    return str(xsh.Screen.Get(1, 1, rows, columns))


def invalidate_screen_cache():
    """命令执行后强制下次重新抓屏，避免把执行前的旧屏幕写进状态。"""
    global CACHED_AT
    CACHED_AT = 0.0


def last_nonempty_line(text):
    for line in reversed(str(text).replace("\r", "").split("\n")):
        if line.strip():
            return line
    return ""


TAIL_END_RE = re.compile(r"[#$>]\s*$")


def prompt_anchor(prompt):
    """从发送前的提示符里取出稳定前缀，用来判断提示符是否回来了。

    root@host:/path#  -> root@host      （cd 换目录后仍然匹配）
    [root@host ~]#    -> [root@host
    mysql>            -> mysql>         （'>  / ->  / SQL> 都对不上）
    """
    text = str(prompt or "").strip()
    if not text:
        return ""
    if ":" in text:
        return text.split(":", 1)[0].strip()
    parts = text.split()
    return parts[0] if parts else text


def wait_for_prompt(pre_text, timeout_ms, poll_ms):
    """判断命令是否结束：提示符以相同前缀回来，且以 # $ > 结尾。

    比逐字符相等宽松（cd/su 之后路径变了也能识别），但仍要求前缀一致，
    避免 mysql 的 '> / -> / SQL> 这类状态提示符被当成"命令结束"。

    屏幕判据终究是文本匹配，仍有误判可能（例如命令输出恰好打印出与
    提示符同形的文本），因此结果里同时给出 promptDetected，
    由调用方自行判断是否需要复核。
    """
    pre_prompt = last_nonempty_line(pre_text).strip()
    anchor = prompt_anchor(pre_prompt)
    if not anchor:
        return False
    deadline = time.monotonic() + max(0, timeout_ms) / 1000.0
    echo_seen = False
    while time.monotonic() < deadline:
        try:
            xsh.Session.Sleep(poll_ms)
        except Exception:
            return False
        current = capture_screen()
        if not echo_seen:
            # 发送瞬间屏幕还没变，最后一行仍是旧提示符，先等回显出现
            if current != pre_text:
                echo_seen = True
            continue
        tail = last_nonempty_line(current).strip()
        if tail.startswith(anchor) and TAIL_END_RE.search(tail):
            return True
    return False


def throttled_screen(interval_ms=None):
    """限频抓屏：两次抓取之间复用上次结果，避免每轮都整屏 Get。"""
    global CACHED_SCREEN, CACHED_AT
    limit = SCREEN_INTERVAL_MS if interval_ms is None else interval_ms
    now = time.monotonic()
    if CACHED_SCREEN is not None and (now - CACHED_AT) * 1000.0 < limit:
        return CACHED_SCREEN
    CACHED_SCREEN = capture_screen()
    CACHED_AT = now
    return CACHED_SCREEN


SCREEN_REQUEST_PATH = os.path.join(SESSION_DIR, "screen.request")
FORCE_STATE = {"flag": False}


def handle_screen_request():
    """外部（网关/守护进程）请求刷新画面时，抓一次屏并更新缓存。

    空闲时脚本不主动抓屏，读屏一律走这个按需通道，避免挂机时的周期调用。
    """
    global CACHED_SCREEN, CACHED_AT
    try:
        if not os.path.exists(SCREEN_REQUEST_PATH):
            return False
    except OSError:
        return False
    try:
        os.remove(SCREEN_REQUEST_PATH)
    except OSError:
        pass
    CACHED_SCREEN = capture_screen()
    CACHED_AT = time.monotonic()
    FORCE_STATE["flag"] = True
    return True


def write_state():
    global LAST_STATE, LAST_TOUCH_AT, LAST_SCREEN, LAST_META
    if is_idle():
        # 空闲时完全不碰 Xshell 原生接口：沿用上次结果，只维护心跳。
        # 需要新画面时由外部写 screen.request，由 handle_screen_request() 触发一次抓取。
        screen = CACHED_SCREEN if CACHED_SCREEN is not None else ""
        meta = META_CACHE["value"] if META_CACHE["value"] is not None else cached_metadata(10.0)
    else:
        screen = throttled_screen(SCREEN_INTERVAL_MS)
        meta = cached_metadata(META_TTL_S)
    now = time.monotonic()
    if (not FORCE_STATE["flag"]) and screen == LAST_SCREEN and meta == LAST_META and os.path.exists(STATE_PATH):
        # 内容未变：只刷新修改时间当心跳，跳过整份 JSON 序列化与写盘
        if now - LAST_TOUCH_AT >= 1.0:
            try:
                os.utime(STATE_PATH, None)
            except OSError:
                pass
            LAST_TOUCH_AT = now
        return
    state = {
        "protocol": PROTOCOL,
        "sessionId": BRIDGE_ID,
        "metadata": meta,
        "screen": screen,
    }
    serialized = json.dumps(state, ensure_ascii=False, sort_keys=True)
    forced = FORCE_STATE["flag"]
    if forced or serialized != LAST_STATE or not os.path.exists(STATE_PATH):
        atomic_write_json(STATE_PATH, state)
        LAST_STATE = serialized
        LAST_TOUCH_AT = now
    LAST_SCREEN = screen
    LAST_META = meta
    FORCE_STATE["flag"] = False


def _collect_review(job, analysis):
    """弹窗展示用的命中信息：优先用网关算好的结果，缺失再本地重算。"""
    review = job.get("safetyReview") or {}
    findings = list(review.get("findings") or [])
    auto = list(review.get("autoApproved") or [])
    if not findings and analysis:
        findings = list(analysis.get("findings") or [])
    if not auto and analysis:
        auto = list(analysis.get("autoApproved") or [])
    return findings, auto


def _highlight_spans(text, findings):
    """把命中片段用【】圈出来。MessageBox 不支持富文本，只能靠符号突出。"""
    spans = []
    for finding in findings:
        raw = str(finding.get("match") or "")
        if not raw:
            continue
        index = finding.get("index")
        start = index if isinstance(index, int) and index >= 0 and text[index:index + len(raw)] == raw else -1
        if start < 0:
            start = text.find(raw)
        if start < 0:
            continue
        spans.append((start, start + len(raw)))
    spans.sort(reverse=True)
    last_start = None
    for start, end in spans:
        if last_start is not None and end > last_start:
            continue  # 与已标记片段重叠，跳过以免嵌套
        text = text[:start] + "【" + text[start:end] + "】" + text[end:]
        last_start = start
    return text


def approval_message(job, analysis=None):
    action = job.get("action", {})
    findings, auto = _collect_review(job, analysis)
    if action.get("type") == "send":
        operation = "发送终端输入" + ("并按回车" if action.get("enter", False) else "（不按回车）")
        raw_input = str(action.get("text", ""))
        marked = _highlight_spans(raw_input, findings) if findings else raw_input
        exact_input = json.dumps(marked, ensure_ascii=False)
        for codepoint in range(0x202A, 0x202F):
            exact_input = exact_input.replace(chr(codepoint), "\\u" + format(codepoint, "04x"))
        for codepoint in range(0x2066, 0x206A):
            exact_input = exact_input.replace(chr(codepoint), "\\u" + format(codepoint, "04x"))
    else:
        operation = "发送 Ctrl+C 中断当前命令"
        exact_input = "Ctrl+C"
    remote_address = str(metadata().get("remoteAddress") or "未知主机")

    header = ["AI Agent 请求执行一个终端操作。", ""]
    if findings:
        header.append("⚠ 需要你重点确认：" + str(len(findings)) + " 处")
        header.append("────────────────────────────")
        for order, finding in enumerate(findings[:6], 1):
            header.append(str(order) + ") 规则：" + str(finding.get("category")))
            header.append("   片段：" + str(finding.get("match") or "")[:160])
            reason = str(finding.get("reason") or "")
            if reason:
                header.append("   原因：" + reason)
        if len(findings) > 6:
            header.append("…… 另有 " + str(len(findings) - 6) + " 处命中")
        header.append("────────────────────────────")
        if auto:
            header.append("另有 " + str(len(auto)) + " 处命令替换已解析为只读，未计入上表。")
        header.append("其余命令部分未命中规则，可跳过不看。")
        header.append("")
    elif auto:
        header.append("命令含 " + str(len(auto)) + " 处命令替换，已解析：内部均为只读命令。")
        header.append("")

    rules_line = ""
    if findings:
        names = []
        for finding in findings:
            name = str(finding.get("category"))
            if name not in names:
                names.append(name)
        rules_line = "命中规则：" + "、".join(names) + "\n\n"

    # MessageBox 高度有限，超长命令会被截掉底部按钮；命中片段已在顶部单列，
    # 这里只保证能看个大概。
    shown_input = exact_input
    if len(shown_input) > 2000:
        shown_input = shown_input[:2000] + "…（已截断，原文共 %d 字符）" % len(exact_input)

    return (
        "\n".join(header) + "\n"
        + "目标主机：" + remote_address + "\n"
        "Agent：" + str(job.get("agentId", "unknown-agent")) + "\n"
        "操作：" + operation + "\n"
        "风险等级：" + RISK_LABELS.get(str(action.get("riskLevel", "")), "未说明") + "\n\n"
        "为什么要做：\n" + str(action.get("explanation", "")) + "\n\n"
        "预期结果：\n" + str(action.get("expectedOutcome", "")) + "\n\n"
        "完整命令（【】内为需要你确认的片段，反斜杠表示转义字符）：\n---\n" + shown_input + "\n---\n\n"
        + rules_line
        + "只有在你理解并同意以上内容时才点击“是”。点击“否”不会向服务器发送任何内容。"
    )


def request_user_approval(job, analysis=None):
    try:
        # Xshell MessageBox nType=4 displays Yes/No; return value 6 means Yes.
        return int(xsh.Dialog.MessageBox(approval_message(job, analysis), "Xshell Agent Bridge 安全确认", 4)) == 6
    except Exception as error:
        raise RuntimeError("无法显示 Xshell 安全确认框，已拒绝执行：" + str(error))


# ---------------------------------------------------------------------------
# 命令体检：解析 $( ) 与反引号内部内容，只读的自动放行，其余交人工确认。
# 规则必须与 src/core.mjs 的 analyzeCommand 保持一致，否则会出现网关放行、
# 脚本又弹窗（或反之）的不一致。
# ---------------------------------------------------------------------------

READONLY_COMMANDS = frozenset((
    "cat", "head", "tail", "grep", "egrep", "fgrep", "awk", "gawk", "sed", "cut", "tr",
    "sort", "uniq", "wc", "ls", "df", "du", "free", "ps", "pgrep", "pidof",
    "pwd", "whoami", "id", "uname", "date", "stat", "readlink", "realpath",
    "basename", "dirname", "echo", "printf", "test", "expr", "true", "false", "seq",
    "column", "lsblk", "lscpu", "nproc", "uptime", "which", "type", "printenv", "find",
))

# 会把这些只读工具变成写操作参数。
WRITE_FLAGS = {
    "sort": re.compile(r"(?:^|\s)(?:-o|--output)(?:\s|=|$)"),
    "date": re.compile(r"(?:^|\s)(?:-s|--set)(?:\s|=|$)"),
    "sed": re.compile(r"(?:^|\s)-i|--in-place"),
    "find": re.compile(r"(?:^|\s)(?:-delete|-exec|-execdir|-ok|-okdir|-fprint\w*|-fls)\b"),
    "awk": re.compile(r"system\s*\(|print\s*\|"),
    "gawk": re.compile(r"system\s*\(|print\s*\|"),
    "ls": re.compile(r"(?:^|\s)--?R\b"),
}

# 文本级解释器检测（保留原有两条规则）；命令替换那条改由结构解析处理。
INTERPRETER_PATTERNS = DYNAMIC_EXECUTION_PATTERNS[:2]
DYNAMIC_ONLY_PATTERNS = (
    ("动态变量或命令替换执行", re.compile(r"(?:^|[\r\n;&|]\s*)(?:eval|source)\b", re.I)),
    ("动态变量或命令替换执行", re.compile(r"(?:^|[\r\n;&|]\s*)\.\s+", re.I)),
)
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SUBST_HEAD_RE = re.compile(r"^_{9,}")
_VAR_HEAD_RE = re.compile(r"^\$\{?[A-Za-z_]")


def _split_shell_segments(text):
    """按 ; & | 换行切段，跳过引号内与转义字符。"""
    segments = []
    buffer = ""
    in_single = False
    in_double = False
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == "\\":
            buffer += text[i:i + 2]
            i += 2
            continue
        if in_single:
            buffer += ch
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = True
            buffer += ch
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buffer += ch
            i += 1
            continue
        if not in_double and ch in ";&|\n":
            segments.append(buffer)
            buffer = ""
            while i < length and text[i] in ";&|\n":
                i += 1
            continue
        buffer += ch
        i += 1
    if buffer.strip():
        segments.append(buffer)
    return segments


def _first_command(tokens):
    """跳过前导 VAR=value 赋值，返回 (命令名, 参数串, 位置)。"""
    index = 0
    while index < len(tokens) and _ASSIGN_RE.match(tokens[index]):
        index += 1
    if index >= len(tokens):
        return None, "", index
    name = tokens[index].split("/")[-1].strip("\"'").lower()
    return name, " ".join(tokens[index + 1:]), index


def _is_readonly_pipeline(inner):
    cleaned = re.sub(r"\d?>&\d", " ", str(inner or "")).replace("&>", " ")
    if re.search(r">>?", cleaned):
        return False
    segments = _split_shell_segments(cleaned)
    if not segments:
        return False
    for segment in segments:
        tokens = segment.strip().split()
        if not tokens:
            continue
        name, args, _ = _first_command(tokens)
        if name is None:
            continue
        if name not in READONLY_COMMANDS:
            return False
        flag = WRITE_FLAGS.get(name)
        if flag and flag.search(args):
            return False
    return True


def _extract_substitutions(text):
    """找出所有 $(...) 与 `...`，处理嵌套、引号与转义。"""
    found = []
    i = 0
    length = len(text)
    in_single = False
    in_double = False
    while i < length:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = True
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if ch == "$" and i + 1 < length and text[i + 1] == "(":
            start = i
            depth = 1
            j = i + 2
            single = False
            double = False
            while j < length and depth > 0:
                inner_ch = text[j]
                if inner_ch == "\\":
                    j += 2
                    continue
                if single:
                    if inner_ch == "'":
                        single = False
                    j += 1
                    continue
                if inner_ch == "'" and not double:
                    single = True
                    j += 1
                    continue
                if inner_ch == '"' and not single:
                    double = not double
                    j += 1
                    continue
                if inner_ch == "(":
                    depth += 1
                elif inner_ch == ")":
                    depth -= 1
                j += 1
            end = j if depth == 0 else length
            found.append({
                "kind": "command",
                "raw": text[start:end],
                "inner": text[start + 2:max(start + 2, end - 1)],
                "index": start,
            })
            i = end
            continue
        if ch == "`":
            start = i
            j = i + 1
            while j < length:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "`":
                    break
                j += 1
            end = min(j + 1, length)
            found.append({
                "kind": "backtick",
                "raw": text[start:end],
                "inner": text[start + 1:j],
                "index": start,
            })
            i = end
            continue
        i += 1
    return found


def _describe_reject(inner):
    for segment in _split_shell_segments(str(inner or "")):
        tokens = segment.strip().split()
        if not tokens:
            continue
        name, args, _ = _first_command(tokens)
        if name is None:
            continue
        if name not in READONLY_COMMANDS:
            return "内部命令 “%s” 不在只读白名单内" % name
        flag = WRITE_FLAGS.get(name)
        if flag and flag.search(args):
            return "内部 %s 带了会写文件的参数" % name
    if re.search(r">>?", re.sub(r"\d?>&\d", " ", str(inner or ""))):
        return "内部有输出重定向，会写文件"
    return "内部结构无法静态确认"


def analyze_command(text):
    """返回 {category, findings, substitutions, autoApproved}。"""
    normalized = re.sub(r"\\\r?\n", " ", str(text or ""))
    findings = []

    for category, pattern in HARD_BLOCKED_INPUT_PATTERNS:
        match = pattern.search(normalized)
        if match:
            findings.append({
                "tier": "hard", "category": category, "match": match.group(0),
                "index": match.start(), "reason": "命中高危命令特征",
            })

    for category, pattern in INTERPRETER_PATTERNS:
        match = pattern.search(normalized)
        if match:
            findings.append({
                "tier": "dynamic", "category": category, "match": match.group(0)[:200],
                "index": match.start(), "reason": "命中把内容交给解释器执行的写法",
            })

    substitutions = []
    for entry in _extract_substitutions(normalized):
        nested = analyze_command(entry["inner"])
        nested_hard = next((f for f in nested["findings"] if f["tier"] == "hard"), None)
        item = dict(entry)
        if nested_hard:
            base = nested_hard["category"].replace("（命令替换内部）", "")
            item["verdict"] = "blocked"
            item["nested_category"] = base
            item["reason"] = "命令替换内部命中高危规则：" + base
        elif not _is_readonly_pipeline(entry["inner"]):
            item["verdict"] = "blocked"
            item["reason"] = _describe_reject(entry["inner"])
        else:
            item["verdict"] = "readonly"
            item["reason"] = "内部仅调用只读命令"
        substitutions.append(item)

    for item in substitutions:
        if item["verdict"] != "blocked":
            continue
        base = item.get("nested_category")
        findings.append({
            "tier": "hard" if base else "dynamic",
            "category": (base + "（命令替换内部）") if base else "动态变量或命令替换执行",
            "match": item["raw"],
            "index": item["index"],
            "reason": item["reason"],
        })

    # 命令位置检查：替换结果或变量被直接当作命令执行时，实际命令静态不可知。
    masked = normalized
    for item in sorted(substitutions, key=lambda x: x["index"], reverse=True):
        placeholder = "_" * max(9, len(item["raw"]))
        masked = masked[:item["index"]] + placeholder + masked[item["index"] + len(item["raw"]):]
    cursor = 0
    for segment in _split_shell_segments(masked):
        segment_start = masked.find(segment, cursor)
        if segment_start >= 0:
            cursor = segment_start + len(segment)
        segment_start = max(0, segment_start)
        tokens = segment.strip().split()
        if not tokens:
            continue
        name, _args, index = _first_command(tokens)
        if name is None or index >= len(tokens):
            continue
        head = tokens[index].strip("\"'")
        covered = any(
            item["verdict"] == "blocked" and abs(item["index"] - segment_start) <= 2
            for item in substitutions
        )
        if _SUBST_HEAD_RE.match(head):
            if not covered:
                findings.append({
                    "tier": "dynamic", "category": "动态变量或命令替换执行",
                    "match": "$( ... )", "index": segment_start,
                    "reason": "命令替换的结果被直接当作命令执行",
                })
        elif _VAR_HEAD_RE.match(head):
            findings.append({
                "tier": "dynamic", "category": "动态变量或命令替换执行",
                "match": head[:120], "index": segment_start,
                "reason": "变量被当作命令执行，真正执行的命令静态不可知",
            })

    for category, pattern in DYNAMIC_ONLY_PATTERNS:
        match = pattern.search(normalized)
        if match:
            findings.append({
                "tier": "dynamic", "category": category, "match": match.group(0),
                "index": match.start(), "reason": "命中 eval/source 或点号执行",
            })

    findings.sort(key=lambda f: f["index"])
    seen = set()
    unique = []
    for finding in findings:
        key = (finding["tier"], finding["category"], finding["index"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    hard = next((f for f in unique if f["tier"] == "hard"), None)
    return {
        "category": hard["category"] if hard else (unique[0]["category"] if unique else None),
        "findings": unique,
        "substitutions": substitutions,
        "autoApproved": [s for s in substitutions if s["verdict"] == "readonly"],
    }


def hard_blocked_operation(text):
    return analyze_command(text)["category"]


def execute_job(job):
    action = job.get("action", {})
    result = {"acceptedByXshell": False, "confirmationShown": False, "approvedByUser": False}
    try:
        mode = job.get("safetyMode", "safe")
        if mode not in ("safe", "normal", "full"):
            raise RuntimeError("未知的终端安全模式，已拒绝执行。")
        action_type = action.get("type")
        if action_type not in ("send", "interrupt"):
            raise RuntimeError("unsupported action: " + str(action_type))

        analysis = None
        blocked_category = None
        if action_type == "send":
            # 本地再算一遍，既用于 safe 模式硬拦截，也给弹窗提供命中详情。
            analysis = analyze_command(action.get("text", ""))
            if mode != "full":
                blocked_category = analysis["category"]
        if mode == "safe" and blocked_category:
            raise RuntimeError(
                "企业安全模式已硬性拦截 Agent 的“"
                + blocked_category
                + "”操作。该命令没有发送；如确有需要，请用户在 Xshell 中亲自输入。"
            )

        confirmation_required = mode == "safe" or (
            mode == "normal" and (
                job.get("confirmationRequired") is not False
                or action_type == "interrupt"
                or bool(blocked_category)
                or action.get("riskLevel") in ("high", "critical")
            )
        )
        if confirmation_required:
            result["approvedByUser"] = request_user_approval(job, analysis)
            result["confirmationShown"] = True
            if not result["approvedByUser"]:
                raise RuntimeError("用户在 Xshell 安全确认框中拒绝了该操作。")

        pre_screen = capture_screen()
        if action_type == "send":
            xsh.Screen.Send(action.get("text", ""))
            if action.get("enter", False):
                xsh.Screen.Send("\r")
        else:
            xsh.Screen.Send(chr(3))
        result["acceptedByXshell"] = True
        # 给回显和首批输出一点时间落到屏幕上，再让主循环抓新图。
        if SETTLE_MS > 0:
            try:
                xsh.Session.Sleep(SETTLE_MS)
            except Exception:
                pass
        # 等命令真正结束（提示符回来）再写结果：客户端收到 completed 时，
        # 屏幕里已经是最终输出，不必再补一次 read_screen。
        # promptDetected=False 表示等到超时也没看到提示符，命令可能仍在执行，
        # 客户端必须据此决定是继续等还是先打断，不能直接发下一条。
        detected = True
        if WAIT_PROMPT_MS > 0 and (action_type == "interrupt" or action.get("enter", False)):
            wait_started = time.monotonic()
            detected = wait_for_prompt(pre_screen, WAIT_PROMPT_MS, PROMPT_POLL_MS)
            result["waitedMs"] = int((time.monotonic() - wait_started) * 1000)
        result["promptDetected"] = detected
        invalidate_screen_cache()
        atomic_write_json(
            RESULT_PATH,
            {
                "jobId": job["id"],
                "job": job,
                "ok": True,
                "result": result,
            },
        )
    except Exception as error:
        atomic_write_json(
            RESULT_PATH,
            {"jobId": job["id"], "job": job, "ok": False, "error": str(error), "result": result},
        )


def valid_transfer_id(value):
    value = str(value)
    return len(value) == 36 and all(character in "0123456789abcdef-" for character in value.lower())


def transfer_state(transfer_id, status, stage, error=None):
    value = {
        "transferId": transfer_id,
        "status": status,
        "stage": stage,
        "updatedAt": time.time(),
    }
    if error:
        value["error"] = str(error)
    return value


def process_desktop_launch_requests():
    os.makedirs(DESKTOP_LAUNCH_ROOT, exist_ok=True)
    for name in sorted(os.listdir(DESKTOP_LAUNCH_ROOT)):
        if not name.endswith(".request.json"):
            continue
        request_path = os.path.join(DESKTOP_LAUNCH_ROOT, name)
        active_path = request_path[:-len(".request.json")] + ".active.json"
        try:
            os.replace(request_path, active_path)
        except OSError:
            continue

        transfer_id = name[:-len(".request.json")]
        transfer_dir = os.path.abspath(os.path.join(TRANSFER_ROOT, transfer_id))
        progress_path = os.path.join(transfer_dir, "progress.json")
        result_path = os.path.join(transfer_dir, "result.json")
        try:
            request = read_json(active_path)
            if request.get("protocol") != DESKTOP_LAUNCH_PROTOCOL:
                raise RuntimeError("不支持的桌面启动协议。")
            if request.get("transferId") != transfer_id or not valid_transfer_id(transfer_id):
                raise RuntimeError("文件传输任务 ID 不合法。")
            if os.path.commonpath([TRANSFER_ROOT, transfer_dir]) != TRANSFER_ROOT:
                raise RuntimeError("文件传输任务路径越界。")

            spec_path = os.path.join(transfer_dir, "spec.json")
            launch_path = os.path.join(transfer_dir, "launch.cmd")
            if not os.path.isfile(spec_path) or not os.path.isfile(launch_path):
                raise RuntimeError("文件传输计划或桌面启动文件不存在。")
            spec = read_json(spec_path)
            if spec.get("transferId") != transfer_id:
                raise RuntimeError("文件传输计划与任务 ID 不匹配。")

            approved = int(xsh.Dialog.MessageBox(
                str(spec.get("texts", {}).get("initialApproval", "是否启动文件传输？")),
                str(spec.get("texts", {}).get("title", "Xshell Agent Bridge 文件传输确认")),
                4,
            )) == 6
            if not approved:
                atomic_write_json(result_path, transfer_state(
                    transfer_id,
                    "rejected",
                    "initial_approval",
                    "用户在 Xshell 文件传输确认框中拒绝了该操作。",
                ))
                continue

            os.startfile(launch_path)
            atomic_write_json(progress_path, transfer_state(
                transfer_id,
                "awaiting_user",
                "authentication_and_transfer",
            ))
        except Exception as error:
            if valid_transfer_id(transfer_id) and os.path.isdir(transfer_dir):
                atomic_write_json(result_path, transfer_state(
                    transfer_id,
                    "failed",
                    "desktop_launch",
                    error,
                ))
        finally:
            try:
                os.remove(active_path)
            except OSError:
                pass


def sleep_or_exit(milliseconds):
    """会话关闭后 xsh.Session 已不可用，Sleep 会抛 TypeError。

    返回 False 表示会话已结束，主循环应当退出，而不是继续抛异常。
    """
    try:
        sleep = getattr(xsh.Session, "Sleep", None)
        if not callable(sleep):
            return False
        note_step("sleep")
        sleep(milliseconds)
        return True
    except Exception:
        return False


STEP_PATH = os.path.join(PROJECT_ROOT, "data", "last-step.txt")
LAST_STEP = {"name": None, "at": 0.0}
LOOP_COUNT = {"n": 0}


def note_step(name):
    """崩溃面包屑：记录当前正在调用哪个原生接口。

    Xshell 是原生进程，脚本宿主崩溃时 Python 的 try/except 没有机会执行，
    只能靠事先写到磁盘的标记推断死在哪一步。最多每秒写一次，避免自身开销。
    """
    now = time.monotonic()
    if LAST_STEP["name"] == name and now - LAST_STEP["at"] < 1.0:
        return
    LAST_STEP["name"] = name
    LAST_STEP["at"] = now
    try:
        with open(STEP_PATH, "w", encoding="utf-8") as handle:
            handle.write("%s loop=%d step=%s\n" % (
                time.strftime("%Y-%m-%d %H:%M:%S"), LOOP_COUNT["n"], name))
    except Exception:
        pass


def _main_loop():
    global LAST_ACTIVITY_AT
    xsh.Screen.Synchronous = True
    os.makedirs(SESSION_DIR, exist_ok=True)
    os.makedirs(DESKTOP_LAUNCH_ROOT, exist_ok=True)
    write_state()

    while True:
        LOOP_COUNT["n"] += 1
        # 停止信号每 40 轮检查一次（约 10 秒）即可：E: 盘挂了加密驱动，
        # 每次 stat 都要过驱动，能少一次就少一次。
        if LOOP_COUNT["n"] % 40 == 1:
            try:
                if os.path.exists(STOP_PATH) and os.path.getmtime(STOP_PATH) >= STARTED_AT:
                    break
            except OSError:
                pass
        try:
            handle_screen_request()
        except Exception as error:
            record_loop_error("screen_request", error)
        try:
            write_state()
        except Exception as error:
            record_loop_error("write_state", error)

        # A failed transfer-launch scan must not disable every terminal
        # confirmation. Keep these two independent queues isolated.
        try:
            process_desktop_launch_requests()
        except Exception as error:
            record_loop_error("desktop_launch", error)

        try:
            if os.path.exists(COMMAND_PATH) and not os.path.exists(ACTIVE_PATH):
                # Claim before execution. An uncertain input is never replayed after a crash.
                os.replace(COMMAND_PATH, ACTIVE_PATH)
                LAST_ACTIVITY_AT = time.monotonic()
                execute_job(read_json(ACTIVE_PATH))
                LAST_ACTIVITY_AT = time.monotonic()
                write_state()
        except Exception as error:
            record_loop_error("command_dispatch", error)
        if not sleep_or_exit(IDLE_POLL_MS if is_idle() else POLL_MS):
            break


def Main():
    """Xshell 的脚本入口。收尾阶段（关窗口/断连）的异常要吞掉，
    否则 Xshell 会弹出 Traceback 对话框。"""
    try:
        _main_loop()
    except Exception as error:
        try:
            record_loop_error("main", error)
        except Exception:
            pass
