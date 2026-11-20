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


def approval_message(job):
    action = job.get("action", {})
    if action.get("type") == "send":
        operation = "发送终端输入" + ("并按回车" if action.get("enter", False) else "（不按回车）")
        exact_input = json.dumps(str(action.get("text", "")), ensure_ascii=False)
        for codepoint in range(0x202A, 0x202F):
            exact_input = exact_input.replace(chr(codepoint), "\\u" + format(codepoint, "04x"))
        for codepoint in range(0x2066, 0x206A):
            exact_input = exact_input.replace(chr(codepoint), "\\u" + format(codepoint, "04x"))
    else:
        operation = "发送 Ctrl+C 中断当前命令"
        exact_input = "Ctrl+C"
    remote_address = str(metadata().get("remoteAddress") or "未知主机")
    return (
        "AI Agent 请求执行一个终端操作。\n\n"
        "目标主机：" + remote_address + "\n"
        "Agent：" + str(job.get("agentId", "unknown-agent")) + "\n"
        "操作：" + operation + "\n"
        "风险等级：" + RISK_LABELS.get(str(action.get("riskLevel", "")), "未说明") + "\n\n"
        "为什么要做：\n" + str(action.get("explanation", "")) + "\n\n"
        "预期结果：\n" + str(action.get("expectedOutcome", "")) + "\n\n"
        "将要发送的完整内容（引号内为输入，反斜杠表示转义字符）：\n---\n" + exact_input + "\n---\n\n"
        "只有在你理解并同意以上内容时才点击“是”。点击“否”不会向服务器发送任何内容。"
    )


def request_user_approval(job):
    try:
        # Xshell MessageBox nType=4 displays Yes/No; return value 6 means Yes.
        return int(xsh.Dialog.MessageBox(approval_message(job), "Xshell Agent Bridge 安全确认", 4)) == 6
    except Exception as error:
        raise RuntimeError("无法显示 Xshell 安全确认框，已拒绝执行：" + str(error))


def hard_blocked_operation(text):
    normalized = re.sub(r"\\\r?\n", " ", str(text or ""))
    for category, pattern in HARD_BLOCKED_INPUT_PATTERNS + DYNAMIC_EXECUTION_PATTERNS:
        if pattern.search(normalized):
            return category
    return None


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

        blocked_category = None
        if action_type == "send" and mode != "full":
            blocked_category = hard_blocked_operation(action.get("text", ""))
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
            result["approvedByUser"] = request_user_approval(job)
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
