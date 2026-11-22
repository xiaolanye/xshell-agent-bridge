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



# 命令体检与确认框文案。判定必须与 src/command-analysis.mjs 一致。

_FLAGS = re.ASCII | re.IGNORECASE
DELETE_COMMANDS = set([
    "rm", "rmdir", "unlink", "shred", "remove-item", "clear-content", "erase", "del", "rd",
])
SHUTDOWN_COMMANDS = set(["shutdown", "reboot", "poweroff", "halt"])
DISK_COMMANDS = set(["wipefs", "blkdiscard", "fdisk", "cfdisk", "sfdisk", "format-volume"])
WRAPPERS = set(["sudo", "command", "env", "xargs", "nohup", "time", "nice", "exec", "builtin"])
WRAPPER_ARG_OPTIONS = {
    "sudo": set(["-u", "-g", "-p", "-h", "-C", "-D", "-T", "-R", "-U", "--user", "--group", "--prompt", "--host", "--chdir", "--role", "--other-user", "--close-from", "--command-timeout"]),
    "command": set(),
    "env": set(["-u", "-C", "-S", "--unset", "--chdir", "--split-string", "--default-signal", "--ignore-signal", "--block-signal", "--argv0"]),
    "xargs": set(["-a", "-d", "-E", "-I", "-J", "-L", "-l", "-n", "-P", "-s", "--arg-file", "--delimiter", "--eof", "--replace", "--max-lines", "--max-args", "--max-procs", "--max-chars"]),
    "nohup": set(),
    "time": set(["-f", "-o", "--format", "--output"]),
    "nice": set(["-n", "--adjustment"]),
    "exec": set(["-a"]),
    "builtin": set(),
}
BARE_READONLY = set([
    "cat", "head", "tail", "grep", "egrep", "fgrep", "awk", "gawk", "sed", "cut", "tr",
    "sort", "uniq", "wc", "ls", "df", "du", "free", "ps", "pgrep", "pidof",
    "pwd", "whoami", "id", "uname", "date", "stat", "readlink", "realpath",
    "basename", "dirname", "echo", "printf", "test", "expr", "true", "false", "seq",
    "column", "lsblk", "lscpu", "nproc", "uptime", "which", "type", "printenv", "find",
    "hostname", "ss", "jq", "vmstat", "iostat",
])
RESTRICTED_READONLY = set(["ip", "journalctl", "systemctl", "docker", "podman", "kubectl", "curl"])
INTERPRETERS = set([
    "sh", "bash", "python", "python3", "node", "perl", "ruby", "php", "lua", "pwsh", "powershell", "cmd", "cmd.exe",
])
VERSION_FLAGS = set(["--version", "-V", "-v"])
IP_OBJECTS = set(["show", "list", "a", "r", "addr", "address", "route", "link"])
IP_WRITE = set(["add", "del", "delete", "set", "change", "replace", "flush"])
SYSTEMCTL_OK = set(["status", "show", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "cat"])
SYSTEMCTL_ARG = set(["-t", "--type", "-p", "--property", "--state", "-o", "--output", "--root"])
DOCKER_DIRECT = set(["ps", "images", "logs", "inspect", "stats", "top", "info", "version", "port", "diff"])
KUBE_OK = set(["get", "describe", "logs", "top", "version", "cluster-info", "api-resources"])
KUBE_ARG = set(["-n", "--namespace", "--context", "--kubeconfig", "-o", "--output", "-l", "--selector", "--field-selector", "--sort-by", "--cluster"])
CURL_ARG = set(["-H", "--header", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "--connect-timeout", "-m", "--max-time", "--retry", "--retry-delay", "-u", "--user", "--proxy"])
PIPE_TO_SHELL = re.compile(
    r"\b(?:base64|openssl\s+enc|xxd\s+-r|curl|wget)\b[^\r\n]{0,1000}"
    r"\|\s*(?:(?:sudo|env|command|nohup)\s+)*(?:/(?:usr/)?bin/)?(?:ba)?sh\b",
    _FLAGS,
)
SCRIPT_DELETE = re.compile(
    r"\b(?:os\.(?:remove|unlink)|shutil\.rmtree|fileutils\.rm_rf|"
    r"fs\.(?:rm|unlink)(?:sync)?|[a-z_$][\w$]*\.unlink)\s*\(",
    _FLAGS,
)
SQL_PATTERN = re.compile(
    r"(?:^|[\s;\"'`])(?:drop\s+(?:database|schema|table|view|index|user)|"
    r"truncate\s+(?:table\s+)?|delete\s+from)\b",
    _FLAGS,
)
DYNAMIC_ONLY = (
    re.compile(r"(?:^|[\r\n;&|]\s*)(?:eval|source)\b", _FLAGS),
    re.compile(r"(?:^|[\r\n;&|]\s*)\.\s+", _FLAGS),
)
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VAR_RE = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")
_BRACE_VAR_RE = re.compile(r"^\$\{[^}]+\}$")
_FIND_WRITE_RE = re.compile(r"(?:^|\s)(?:-delete|-exec|-execdir|-ok|-okdir|-fprint\w*|-fls)\b", re.ASCII)
_DD_OF_RE = re.compile(r"\bof\s*=\s*/dev/", _FLAGS)
_AWK_SYSTEM_RE = re.compile(r"system\s*\(")
_AWK_GETLINE_RE = re.compile(r"\|\s*getline\b", re.ASCII)
_AWK_PRINT_FILE_RE = re.compile(r"\bprintf?\b[^;\n]*>>?\s*[\"'/]", re.ASCII)
_AWK_PRINT_PIPE_RE = re.compile(r"\bprintf?\b[^;\n]*\|\s*[\"']", re.ASCII)
_VACUUM_RE = re.compile(r"^--vacuum-")
_SED_FLAG_SPACE_RE = re.compile(r"^[ \t]+[wWe](?:\s|;|$)")
IMPACTS = (
    ("文件删除或内容清空", "会删除文件或清空文件内容"),
    ("脚本删除文件", "会在脚本里删除文件"),
    ("find 批量删除", "会按条件批量删除文件或执行命令"),
    ("容器或编排资源删除", "会删除容器、镜像或编排资源"),
    ("数据库删除或清空", "会删除或清空数据库里的对象"),
    ("磁盘格式化或擦除", "会格式化或擦除磁盘上的数据"),
    ("软件包卸载", "会卸载系统里的软件包"),
    ("版本库强制清理", "会强制丢掉版本库里尚未提交的内容"),
    ("关机或重启", "会关闭或重新启动这台机器"),
    ("防火墙规则清空", "会清空防火墙规则"),
    ("将编码或下载内容交给命令解释器执行", "会把下载或编码后的内容当作命令执行"),
    ("命令解释器或脚本解释器执行", "会启动解释器执行一段代码"),
    ("动态变量或命令替换执行", "实际要执行的命令在发送前无法确定"),
)
DIALOG_FINDING_LIMIT = 3
DIALOG_FIELD_LIMIT = 120
DIALOG_LINE_BUDGET = 48
DIALOG_CHAR_BUDGET = 1600


def _impact_for(category):
    raw = str(category or "")
    base = raw.replace("（命令替换内部）", "")
    sentence = "需要你确认这段命令会做什么"
    for name, text in IMPACTS:
        if base.startswith(name):
            sentence = text
            break
    if "（命令替换内部）" in raw:
        return sentence + "（发生在命令替换内部）"
    return sentence


def _unquote_word(token):
    out = []
    in_single = False
    in_double = False
    i = 0
    length = len(token)
    while i < length:
        ch = token[i]
        if in_single:
            if ch == "'":
                in_single = False
            else:
                out.append(ch)
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < length:
                out.append(token[i + 1])
                i += 2
                continue
            if ch == '"':
                in_double = False
            else:
                out.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < length:
            out.append(token[i + 1])
            i += 2
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _is_assignment(word):
    return _ASSIGN_RE.match(word) is not None


def _is_variable_word(word):
    return _VAR_RE.match(word) is not None or _BRACE_VAR_RE.match(word) is not None


def _shell_words(segment):
    words = []
    buf = []
    in_single = False
    in_double = False
    i = 0
    length = len(segment)
    while i < length:
        ch = segment[i]
        if in_single:
            buf.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "\\":
            buf.append(segment[i:min(length, i + 2)])
            i += 2
            continue
        if ch == '"':
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = True
            buf.append(ch)
            i += 1
            continue
        if not in_double and ch.isspace():
            if buf:
                words.append("".join(buf))
                buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        words.append("".join(buf))
    return words


def _token_offsets(segment, tokens):
    offsets = []
    cursor = 0
    for token in tokens:
        at = segment.find(token, cursor)
        if at < 0:
            at = cursor
        offsets.append(at)
        cursor = at + len(token)
    return offsets


def _split_shell_segments(text):
    segments = []
    buf = []
    in_single = False
    in_double = False
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if in_single:
            buf.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "\\":
            buf.append(text[i:min(length, i + 2)])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = True
            buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if not in_double and ch in ";\n|&":
            if ch == "&" and ((i + 1 < length and text[i + 1] == ">") or (buf and buf[-1] == ">")):
                buf.append(ch)
                i += 1
                continue
            segment = "".join(buf)
            if segment.strip():
                segments.append(segment)
            buf = []
            while i < length and text[i] in ";|&\n":
                i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf)
    if tail.strip():
        segments.append(tail)
    return segments


def _match_heredoc(text, i):
    if i + 2 >= len(text) or text[i] != "<" or text[i + 1] != "<" or text[i + 2] == "<":
        return None
    j = i + 2
    strip_tabs = False
    if j < len(text) and text[j] == "-":
        strip_tabs = True
        j += 1
    while j < len(text) and text[j] in " \t":
        j += 1
    if j >= len(text) or text[j] in "\n;":
        return None
    delim = []
    quoted = False
    in_single = False
    in_double = False
    while j < len(text):
        ch = text[j]
        if in_single:
            if ch == "'":
                in_single = False
            else:
                delim.append(ch)
            j += 1
            continue
        if in_double:
            if ch == "\\" and j + 1 < len(text):
                delim.append(text[j + 1])
                j += 2
                continue
            if ch == '"':
                in_double = False
            else:
                delim.append(ch)
            j += 1
            continue
        if ch == "\\" and j + 1 < len(text):
            quoted = True
            delim.append(text[j + 1])
            j += 2
            continue
        if ch == "'":
            quoted = True
            in_single = True
            j += 1
            continue
        if ch == '"':
            quoted = True
            in_double = True
            j += 1
            continue
        if ch in " \t\n;&|<>":
            break
        delim.append(ch)
        j += 1
    word = "".join(delim)
    if not word or in_single or in_double:
        return None
    return {"delim": word, "quoted": quoted, "stripTabs": strip_tabs, "end": j}


def _line_is_delim(line, heredoc):
    compare = line.lstrip("\t") if heredoc["stripTabs"] else line
    return compare == heredoc["delim"]


def _read_command_substitution(text, start):
    depth = 1
    j = start + 2
    single = False
    double = False
    length = len(text)
    while j < length and depth > 0:
        ch = text[j]
        if single:
            if ch == "'":
                single = False
            j += 1
            continue
        if ch == "\\":
            j += 2
            continue
        if ch == "'" and not double:
            single = True
            j += 1
            continue
        if ch == '"':
            double = not double
            j += 1
            continue
        if not double and ch == "(":
            depth += 1
        elif not double and ch == ")":
            depth -= 1
        j += 1
    end = j if depth == 0 else length
    inner_end = end - 1 if depth == 0 else end
    return {
        "kind": "command",
        "raw": text[start:end],
        "inner": text[start + 2:max(start + 2, inner_end)],
        "index": start,
        "end": end,
    }


def _read_backtick(text, start):
    j = start + 1
    length = len(text)
    while j < length:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "`":
            j += 1
            break
        j += 1
    closed = j > start + 1 and text[j - 1] == "`"
    return {
        "kind": "backtick",
        "raw": text[start:j],
        "inner": text[start + 1:j - 1 if closed else j],
        "index": start,
        "end": j,
    }


def _scan_shell(text):
    substitutions = []
    blanked = list(text)
    pending = []
    heredoc = None
    in_single = False
    in_double = False
    in_comment = False
    line_start = 0
    i = 0
    length = len(text)

    def blank(frm, to):
        end = min(to, len(blanked))
        for k in range(max(0, frm), end):
            if text[k] != "\n":
                blanked[k] = " "

    def start_pending():
        nonlocal heredoc
        if heredoc is None and pending:
            heredoc = pending.pop(0)

    while i < length:
        if heredoc is not None and (heredoc["quoted"] or i == line_start):
            nl = text.find("\n", i)
            line_end = length if nl < 0 else nl
            line = text[i:line_end]
            if i == line_start and _line_is_delim(line, heredoc):
                blank(i, line_end)
                heredoc = None
                i = length if nl < 0 else nl + 1
                line_start = i
                start_pending()
                continue
            if heredoc["quoted"]:
                blank(i, line_end)
                i = length if nl < 0 else nl + 1
                line_start = i
                continue
        if i >= length:
            break
        ch = text[i]
        if ch == "\n":
            in_comment = False
            i += 1
            line_start = i
            if not in_single and not in_double:
                start_pending()
            continue
        if in_comment:
            blanked[i] = " "
            i += 1
            continue
        if in_single:
            blanked[i] = " "
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "\\":
            if not in_double and heredoc is None and i + 1 < length and text[i + 1] == "\n":
                blanked[i] = " "
                i += 1
                continue
            nxt = min(length, i + 2)
            if in_double or heredoc is not None:
                blank(i, nxt)
            i = nxt
            continue
        if ch == "'" and not in_double:
            in_single = True
            blanked[i] = " "
            i += 1
            continue
        if ch == '"':
            in_double = not in_double
            blanked[i] = " "
            i += 1
            continue
        if in_double:
            if ch == "$" and text[i + 1:i + 3] == "((":
                blank(i, i + 3)
                i += 3
                continue
            if ch == "$" and i + 1 < length and text[i + 1] == "(":
                sub = _read_command_substitution(text, i)
                substitutions.append(sub)
                blank(sub["index"], sub["end"])
                i = sub["end"]
                continue
            if ch == "`":
                sub = _read_backtick(text, i)
                substitutions.append(sub)
                blank(sub["index"], sub["end"])
                i = sub["end"]
                continue
            blanked[i] = " "
            i += 1
            continue
        if ch == "#":
            in_comment = True
            blanked[i] = " "
            i += 1
            continue
        if heredoc is None:
            opener = _match_heredoc(text, i)
            if opener:
                pending.append(opener)
                i = opener["end"]
                continue
        if ch == "$" and i + 1 < length and text[i + 1] == "(":
            if i + 2 < length and text[i + 2] == "(":
                i += 3
                continue
            sub = _read_command_substitution(text, i)
            substitutions.append(sub)
            blank(sub["index"], sub["end"])
            i = sub["end"]
            continue
        if ch == "`":
            sub = _read_backtick(text, i)
            substitutions.append(sub)
            blank(sub["index"], sub["end"])
            i = sub["end"]
            continue
        if heredoc is not None and not heredoc["quoted"]:
            blanked[i] = " "
        i += 1
    return {"substitutions": substitutions, "blanked": "".join(blanked)}

def _mask_substitutions(text, substitutions):
    masked = text
    for entry in sorted(substitutions, key=lambda item: item["index"], reverse=True):
        masked = masked[:entry["index"]] + ("\x01" * len(entry["raw"])) + masked[entry["index"] + len(entry["raw"]):]
    return masked


def _basename_of(word):
    slash = max(word.rfind("/"), word.rfind("\\"))
    return (word[slash + 1:] if slash >= 0 else word).lower()


def _normalize_command_base(token):
    word = _unquote_word(token)
    while word.startswith("("):
        word = word[1:]
    while word.endswith(")"):
        word = word[:-1]
    if not word or "\x01" in word:
        return ""
    return _basename_of(word)


def _is_trusted_command_token(token):
    word = _unquote_word(token)
    while word.startswith("("):
        word = word[1:]
    while word.endswith(")"):
        word = word[:-1]
    if not word or "\x01" in word:
        return False
    if "/" not in word and "\\" not in word:
        return True
    if word.startswith("/bin/") and "/" not in word[5:]:
        return True
    if word.startswith("/usr/bin/") and "/" not in word[9:]:
        return True
    return False


def _trusted_readonly_name(token):
    if not _is_trusted_command_token(token):
        return None
    base = _normalize_command_base(token)
    if base in BARE_READONLY or base in RESTRICTED_READONLY:
        return base
    return None


def _resolve_invocation(tokens):
    i = 0
    leading = False
    while i < len(tokens) and _is_assignment(_unquote_word(tokens[i])):
        leading = True
        i += 1
    env_assign = False
    while i < len(tokens):
        shown = _unquote_word(tokens[i])
        if "\x01" in shown:
            return {"commandIndex": i, "leadingAssign": leading, "envAssign": env_assign, "dynamic": True}
        name = _basename_of(shown.lstrip("(").rstrip(")"))
        if name not in WRAPPERS:
            return {"commandIndex": i, "leadingAssign": leading, "envAssign": env_assign, "dynamic": False}
        arg_opts = WRAPPER_ARG_OPTIONS.get(name, set())
        i += 1
        while i < len(tokens):
            word = _unquote_word(tokens[i])
            if "\x01" in word:
                return {"commandIndex": i, "leadingAssign": leading, "envAssign": env_assign, "dynamic": True}
            if word == "--":
                i += 1
                break
            if name == "env" and _is_assignment(word):
                env_assign = True
                i += 1
                continue
            if word.startswith("-"):
                opt = word.split("=", 1)[0]
                if "=" not in word and opt in arg_opts:
                    i += 2
                    continue
                i += 1
                continue
            break
    return {"commandIndex": -1, "leadingAssign": leading, "envAssign": env_assign, "dynamic": False}


def _operands(words):
    out = []
    for i, word in enumerate(words):
        if word == "--":
            for rest in words[i + 1:]:
                if not rest.startswith("-"):
                    out.append(rest)
            break
        if word.startswith("-"):
            continue
        out.append(word)
    return out


def _short_cluster_has(token, letter):
    return token.startswith("-") and not token.startswith("--") and letter in token[1:]


def _classify_hard(base, arg_tokens):
    args = " ".join(arg_tokens)
    ops = _operands(arg_tokens)
    if base in DELETE_COMMANDS:
        return "文件删除或内容清空"
    if base in SHUTDOWN_COMMANDS:
        return "关机或重启"
    if base == "find" and _FIND_WRITE_RE.search(args):
        return "find 批量删除"
    if base in ("docker", "podman"):
        if "rm" in ops or "rmi" in ops or "prune" in ops:
            return "容器或编排资源删除"
        if "compose" in ops and "down" in ops:
            return "容器或编排资源删除"
    if base == "kubectl" and "delete" in ops:
        return "容器或编排资源删除"
    if base == "helm" and "uninstall" in ops:
        return "容器或编排资源删除"
    if base == "crictl" and ("rm" in ops or "rmi" in ops):
        return "容器或编排资源删除"
    if base in ("apt", "apt-get") and any(word in ("remove", "purge", "autoremove") for word in ops):
        return "软件包卸载"
    if base in ("yum", "dnf") and any(word in ("remove", "erase", "autoremove") for word in ops):
        return "软件包卸载"
    if base == "rpm" and any(word == "-e" for word in arg_tokens):
        return "软件包卸载"
    if base == "apk" and "del" in ops:
        return "软件包卸载"
    if base == "pacman" and any(word.startswith("-R") for word in arg_tokens):
        return "软件包卸载"
    if base in DISK_COMMANDS or base == "mkfs" or base.startswith("mkfs."):
        return "磁盘格式化或擦除"
    if base == "dd" and _DD_OF_RE.search(args):
        return "磁盘格式化或擦除"
    if base == "git":
        if ops and ops[0] == "reset" and any(word == "--hard" for word in arg_tokens):
            return "版本库强制清理"
        if ops and ops[0] == "clean" and any(word == "--force" or _short_cluster_has(word, "f") for word in arg_tokens):
            return "版本库强制清理"
    if base == "systemctl" and ops and ops[0] in ("poweroff", "reboot", "halt"):
        return "关机或重启"
    if base == "init" and arg_tokens and arg_tokens[0] in ("0", "6"):
        return "关机或重启"
    if base in ("iptables", "ip6tables") and any(word in ("-F", "-X", "--flush") for word in arg_tokens):
        return "防火墙规则清空"
    if base == "nft" and len(ops) > 1 and ops[0] == "flush" and ops[1] == "ruleset":
        return "防火墙规则清空"
    return None


def _push_finding(findings, finding):
    findings.append({
        "tier": finding["tier"],
        "category": finding["category"],
        "match": str(finding.get("match") or "")[:240],
        "index": finding["index"],
        "reason": finding["reason"],
    })


def _hard_findings(original, blanked):
    findings = []
    cursor = 0
    for segment in _split_shell_segments(blanked):
        segment_start = blanked.find(segment, cursor)
        if segment_start < 0:
            continue
        cursor = segment_start + len(segment)
        tokens = _shell_words(segment)
        if not tokens:
            continue
        offsets = _token_offsets(segment, tokens)
        resolved = _resolve_invocation(tokens)
        if resolved["commandIndex"] < 0 or resolved["dynamic"]:
            continue
        token = tokens[resolved["commandIndex"]]
        base = _normalize_command_base(token)
        if not base:
            continue
        arg_tokens = []
        for raw in tokens[resolved["commandIndex"] + 1:]:
            word = _unquote_word(raw)
            if word and "\x01" not in word:
                arg_tokens.append(word)
        category = _classify_hard(base, arg_tokens)
        if not category:
            continue
        index = segment_start + offsets[resolved["commandIndex"]]
        end = segment_start + offsets[-1] + len(tokens[-1])
        match = original[index:min(len(original), max(end, index + len(token)), index + 200)]
        _push_finding(findings, {
            "tier": "hard", "category": category, "match": match, "index": index, "reason": "命中高危命令特征",
        })
    script = SCRIPT_DELETE.search(blanked)
    if script:
        _push_finding(findings, {
            "tier": "hard",
            "category": "脚本删除文件",
            "match": original[script.start():script.end()],
            "index": script.start(),
            "reason": "命中高危命令特征",
        })
    sql = SQL_PATTERN.search(blanked)
    if sql:
        _push_finding(findings, {
            "tier": "hard",
            "category": "数据库删除或清空",
            "match": original[sql.start():sql.end()],
            "index": sql.start(),
            "reason": "命中高危命令特征",
        })
    return findings


def _parse_quoted(raw):
    if len(raw) >= 2 and raw[0] == "'" and raw[-1] == "'":
        return {"quoted": True, "content": raw[1:-1], "contentOffset": 1, "literal": True}
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        body = raw[1:-1]
        out = []
        i = 0
        while i < len(body):
            if body[i] == "\\" and i + 1 < len(body):
                out.append(body[i + 1])
                i += 2
                continue
            out.append(body[i])
            i += 1
        content = "".join(out)
        return {"quoted": True, "content": content, "contentOffset": 1, "literal": content == body}
    return {"quoted": False, "content": raw, "contentOffset": 0, "literal": False}


def _db_client_findings(original):
    findings = []
    cursor = 0
    for segment in _split_shell_segments(original):
        segment_start = original.find(segment, cursor)
        if segment_start < 0:
            continue
        cursor = segment_start + len(segment)
        tokens = _shell_words(segment)
        offsets = _token_offsets(segment, tokens)
        resolved = _resolve_invocation(tokens)
        if resolved["commandIndex"] < 0 or resolved["dynamic"]:
            continue
        base = _normalize_command_base(tokens[resolved["commandIndex"]])
        if base in ("mysql", "mariadb"):
            names = ["-e", "--execute"]
        elif base == "psql":
            names = ["-c", "--command"]
        else:
            continue
        args = tokens[resolved["commandIndex"] + 1:]
        arg_offsets = offsets[resolved["commandIndex"] + 1:]
        i = 0
        while i < len(args):
            raw = args[i]
            word = _unquote_word(raw)
            sql = None
            sql_offset = 0
            if word in names:
                if i + 1 >= len(args):
                    i += 1
                    continue
                nxt = args[i + 1]
                parsed = _parse_quoted(nxt)
                sql = parsed["content"] if parsed["quoted"] else _unquote_word(nxt)
                sql_offset = arg_offsets[i + 1] + (parsed["contentOffset"] if parsed["quoted"] else 0)
                i += 1
            else:
                attached = None
                for name in names:
                    if word.startswith(name + "=") or (name.startswith("-") and len(name) == 2 and word.startswith(name) and len(word) > len(name)):
                        attached = name
                        break
                if not attached:
                    i += 1
                    continue
                if word.startswith(attached + "="):
                    sql = word[len(attached) + 1:]
                else:
                    sql = word[len(attached):]
                parsed = _parse_quoted(sql)
                sql = parsed["content"] if parsed["quoted"] else sql
                located = raw.find(sql)
                sql_offset = arg_offsets[i] + (located if located >= 0 else 0)
            if sql and SQL_PATTERN.search(sql):
                index = segment_start + sql_offset
                match = original[index:index + len(sql)] or sql
                _push_finding(findings, {
                    "tier": "hard",
                    "category": "数据库删除或清空",
                    "match": match,
                    "index": index,
                    "reason": "数据库客户端会执行引号里的删除语句",
                })
            i += 1
    return findings


def _extract_dash_c(raw_tokens, base_offsets, segment_start):
    for i, raw in enumerate(raw_tokens):
        if "\x01" in raw:
            return None
        word = _unquote_word(raw)
        if word == "--":
            return None
        if not word.startswith("-") or word.startswith("--"):
            if word.startswith("-"):
                continue
            return None
        marker = word.find("c")
        if marker < 0:
            continue
        c_at = raw.find("c")
        after = raw[c_at + 1:]
        if after:
            parsed = _parse_quoted(after)
            if not parsed["quoted"]:
                return None
            return dict(parsed, contentAbs=segment_start + base_offsets[i] + c_at + 1 + parsed["contentOffset"])
        if i + 1 >= len(raw_tokens):
            return None
        parsed = _parse_quoted(raw_tokens[i + 1])
        if not parsed["quoted"]:
            return None
        return dict(parsed, contentAbs=segment_start + base_offsets[i + 1] + parsed["contentOffset"])
    return None


def _interpreter_findings(original, masked, depth):
    findings = []
    cursor = 0
    for segment in _split_shell_segments(masked):
        segment_start = masked.find(segment, cursor)
        if segment_start < 0:
            continue
        cursor = segment_start + len(segment)
        original_segment = original[segment_start:segment_start + len(segment)]
        tokens = _shell_words(segment)
        if not tokens:
            continue
        offsets = _token_offsets(segment, tokens)
        resolved = _resolve_invocation(tokens)
        if resolved["commandIndex"] < 0:
            continue
        cmd_token = tokens[resolved["commandIndex"]]
        cmd_word = _unquote_word(cmd_token)
        if "\x01" in cmd_word or resolved["dynamic"]:
            continue
        base = _normalize_command_base(cmd_token)
        if base not in INTERPRETERS:
            continue
        arg_tokens = tokens[resolved["commandIndex"] + 1:]
        arg_offsets = offsets[resolved["commandIndex"] + 1:]
        raw_args = [original_segment[arg_offsets[n]:arg_offsets[n] + len(token)] for n, token in enumerate(arg_tokens)]
        trusted = _is_trusted_command_token(cmd_token) and not resolved["leadingAssign"] and not resolved["envAssign"]
        version_only = trusted and raw_args and all(_unquote_word(token) in VERSION_FLAGS for token in raw_args)
        if version_only:
            continue
        if trusted and base in ("sh", "bash"):
            script = _extract_dash_c(raw_args, arg_offsets, segment_start)
            if script:
                inner = analyze_command(script["content"], depth + 1)
                if not inner["findings"]:
                    continue
                hoisted = []
                if script["literal"]:
                    for finding in inner["findings"]:
                        index = script["contentAbs"] + finding["index"]
                        match = str(finding.get("match") or "")
                        if match and original[index:index + len(match)] == match:
                            copied = dict(finding)
                            copied["index"] = index
                            hoisted.append(copied)
                if hoisted:
                    findings.extend(hoisted)
                    continue
        index = segment_start + offsets[resolved["commandIndex"]]
        _push_finding(findings, {
            "tier": "dynamic",
            "category": "命令解释器或脚本解释器执行",
            "match": original[index:index + len(cmd_token)][:200],
            "index": index,
            "reason": "命中把内容交给解释器执行的写法",
        })
    return findings


def _command_position_findings(original, masked, substitutions):
    findings = []
    cursor = 0
    for segment in _split_shell_segments(masked):
        segment_start = masked.find(segment, cursor)
        if segment_start < 0:
            continue
        cursor = segment_start + len(segment)
        tokens = _shell_words(segment)
        if not tokens:
            continue
        offsets = _token_offsets(segment, tokens)
        resolved = _resolve_invocation(tokens)
        if resolved["commandIndex"] < 0:
            continue
        pos = resolved["commandIndex"]
        token = tokens[pos]
        index = segment_start + offsets[pos]
        match = original[index:index + len(token)]
        covered = any(entry["verdict"] == "blocked" and entry["index"] == index for entry in substitutions)
        if covered:
            continue
        word = _unquote_word(token)
        if "\x01" in word or "$(" in match or "`" in match:
            _push_finding(findings, {
                "tier": "dynamic",
                "category": "动态变量或命令替换执行",
                "match": match[:240],
                "index": index,
                "reason": "命令替换的结果被直接当作命令执行",
            })
        elif _is_variable_word(word):
            _push_finding(findings, {
                "tier": "dynamic",
                "category": "动态变量或命令替换执行",
                "match": word[:120],
                "index": index,
                "reason": "变量被当作命令执行，真正执行的命令静态不可知",
            })
    return findings


def _read_redirect_target(text, i):
    while i < len(text) and text[i] in " \t":
        i += 1
    target = []
    in_single = False
    in_double = False
    while i < len(text):
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
            else:
                target.append(ch)
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < len(text):
                target.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_double = False
            else:
                target.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < len(text):
            target.append(text[i + 1])
            i += 2
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch in " \t\n;&|<>":
            break
        target.append(ch)
        i += 1
    return {"target": "".join(target), "end": i}


def _redirect_at(text, i):
    if text.startswith("&>>", i):
        target = _read_redirect_target(text, i + 3)
        return {"safe": target["target"] == "/dev/null", "next": target["end"]}
    if text.startswith("&>", i):
        target = _read_redirect_target(text, i + 2)
        return {"safe": target["target"] == "/dev/null", "next": target["end"]}
    j = i
    while j < len(text) and text[j].isdigit():
        j += 1
    at = j
    if text.startswith(">&", at):
        target = _read_redirect_target(text, at + 2)
        if target["target"].isdigit():
            return {"safe": True, "next": target["end"]}
        return {"safe": target["target"] == "/dev/null", "next": target["end"]}
    if text.startswith(">>", at):
        target = _read_redirect_target(text, at + 2)
        return {"safe": target["target"] == "/dev/null", "next": target["end"]}
    if at < len(text) and text[at] == ">":
        target = _read_redirect_target(text, at + 1)
        return {"safe": target["target"] == "/dev/null", "next": target["end"]}
    return None


def _skip_arithmetic(text, i):
    depth = 2
    in_single = False
    in_double = False
    i += 3
    while i < len(text) and depth > 0:
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "\\":
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = not in_double
            i += 1
            continue
        if not in_double and ch == "(":
            depth += 1
        elif not in_double and ch == ")":
            depth -= 1
        i += 1
    return i


def _has_unsafe_redirect(text):
    in_single = False
    in_double = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "\\":
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = not in_double
            i += 1
            continue
        if in_double:
            i += 1
            continue
        if ch == "<" and i + 1 < len(text) and text[i + 1] == "<":
            i += 2
            continue
        if ch == "$" and text[i + 1:i + 3] == "((":
            i = _skip_arithmetic(text, i)
            continue
        redirect = _redirect_at(text, i)
        if redirect:
            if not redirect["safe"]:
                return True
            i = redirect["next"] if redirect["next"] > i else i + 1
            continue
        i += 1
    return False

def _skip_sed_address(script, i):
    def skip_one(k):
        if k >= len(script):
            return k
        if script[k] == "$":
            return k + 1
        if script[k].isdigit():
            j = k
            while j < len(script) and script[j].isdigit():
                j += 1
            return j
        if script[k] in "/\\":
            delim = script[k + 1] if script[k] == "\\" and k + 1 < len(script) else "/"
            if script[k] == "\\" and k + 1 >= len(script):
                return k
            j = k + (2 if script[k] == "\\" else 1)
            while j < len(script) and script[j] != delim and script[j] != "\n":
                if script[j] == "\\":
                    j += 2
                else:
                    j += 1
            if j < len(script) and script[j] == delim:
                j += 1
            return j
        return k

    nxt = skip_one(i)
    if nxt == i:
        return i
    if nxt < len(script) and script[nxt] in ",~":
        return skip_one(nxt + 1)
    return nxt


def _consume_transform(script, i):
    if i + 1 >= len(script):
        return {"index": i + 1, "writes": False}
    delim = script[i + 1]
    if delim.isspace() or delim == ";":
        return {"index": i + 1, "writes": False}
    k = i + 2

    def find_delim():
        nonlocal k
        while k < len(script):
            if script[k] == "\\" and k + 1 < len(script):
                k += 2
                continue
            if script[k] == "\n":
                return False
            if script[k] == delim:
                k += 1
                return True
            k += 1
        return False

    if not find_delim() or not find_delim():
        return {"index": max(k, i + 1), "writes": False}
    flags = []
    while k < len(script) and script[k] not in " \t;\n":
        flags.append(script[k])
        k += 1
    flag_text = "".join(flags)
    if any(ch in flag_text for ch in "ewW"):
        return {"index": k, "writes": True}
    if _SED_FLAG_SPACE_RE.match(script[k:]):
        return {"index": k, "writes": True}
    return {"index": k, "writes": False}


def _sed_script_writes(script):
    i = 0
    while i < len(script):
        while i < len(script) and (script[i].isspace() or script[i] == ";"):
            i += 1
        if i >= len(script):
            return False
        if script[i] == "#":
            while i < len(script) and script[i] != "\n":
                i += 1
            continue
        i = _skip_sed_address(script, i)
        while i < len(script) and script[i] in " \t":
            i += 1
        if i < len(script) and script[i] == "!":
            i += 1
            while i < len(script) and script[i] in " \t":
                i += 1
        if i >= len(script):
            return False
        cmd = script[i]
        if cmd in "wWe":
            return True
        if cmd in "sy":
            parsed = _consume_transform(script, i)
            if parsed["writes"]:
                return True
            i = parsed["index"]
            continue
        if cmd in "{}":
            i += 1
            continue
        if cmd == ":":
            i += 1
            while i < len(script) and script[i] not in " \t\n;{}":
                i += 1
            continue
        if cmd in "aci":
            i += 1
            while i < len(script) and script[i] not in "\n;":
                i += 1
            continue
        i += 1
    return False


def _sed_writes(tokens):
    words = [_unquote_word(token) for token in tokens]
    saw_script = False
    i = 0
    while i < len(words):
        token = words[i]
        if token == "--":
            if not saw_script and i + 1 < len(words) and _sed_script_writes(words[i + 1]):
                return True
            break
        if token in ("--in-place", "--file") or token.startswith("--in-place=") or token.startswith("--file="):
            return True
        if token in ("-e", "--expression") or token.startswith("--expression="):
            if token.startswith("--expression="):
                script = token[len("--expression="):]
            else:
                i += 1
                script = words[i] if i < len(words) else ""
            saw_script = True
            if script and _sed_script_writes(script):
                return True
            i += 1
            continue
        if token.startswith("--"):
            i += 1
            continue
        if token.startswith("-") and len(token) > 1:
            k = 1
            while k < len(token):
                letter = token[k]
                if letter in "if":
                    return True
                if letter == "e":
                    attached = token[k + 1:]
                    if attached:
                        script = attached
                    else:
                        i += 1
                        script = words[i] if i < len(words) else ""
                    saw_script = True
                    if script and _sed_script_writes(script):
                        return True
                    break
                k += 1
            i += 1
            continue
        if not saw_script:
            saw_script = True
            if _sed_script_writes(token):
                return True
        i += 1
    return False


def _sort_writes(tokens):
    for token in (_unquote_word(item) for item in tokens):
        if token == "--output" or token.startswith("--output=") or _short_cluster_has(token, "o"):
            return True
    return False


def _date_writes(tokens):
    for token in (_unquote_word(item) for item in tokens):
        if token.startswith("+"):
            continue
        if token == "--set" or token.startswith("--set=") or _short_cluster_has(token, "s"):
            return True
    return False


def _awk_program_writes(program):
    if _AWK_SYSTEM_RE.search(program):
        return True
    if _AWK_GETLINE_RE.search(program):
        return True
    no_parens = re.sub(r"\([^()]*\)", "", program)
    if _AWK_PRINT_FILE_RE.search(no_parens) or _AWK_PRINT_PIPE_RE.search(no_parens):
        return True
    return False


def _awk_writes(tokens):
    words = [_unquote_word(token) for token in tokens]
    program = []
    saw_program = False
    i = 0
    while i < len(words):
        token = words[i]
        if token == "--":
            if not saw_program and i + 1 < len(words):
                program.append(words[i + 1])
            break
        if token in ("-f", "--file") or token.startswith("--file=") or (token.startswith("-f") and not token.startswith("--")):
            return True
        if token in ("-e", "--source") or token.startswith("--source=") or (token.startswith("-e") and len(token) > 2 and not token.startswith("--")):
            if token.startswith("--source="):
                src = token[len("--source="):]
            elif token.startswith("-e") and len(token) > 2:
                src = token[2:]
            else:
                i += 1
                src = words[i] if i < len(words) else ""
            saw_program = True
            program.append(src)
            i += 1
            continue
        if token.startswith("-"):
            if "=" not in token and token in ("-v", "-F", "-W", "--field-separator", "--assign"):
                i += 1
            i += 1
            continue
        if not saw_program:
            saw_program = True
            program.append(token)
        i += 1
    return _awk_program_writes("\n".join(program))


def _find_writes(tokens):
    return _FIND_WRITE_RE.search(" ".join(_unquote_word(token) for token in tokens)) is not None


def _skip_options(words, arg_options):
    i = 0
    while i < len(words) and words[i].startswith("-"):
        name = words[i].split("=", 1)[0]
        if "=" not in words[i] and name in arg_options:
            i += 2
        else:
            i += 1
    return i


def _ip_readonly(tokens):
    words = [_unquote_word(token) for token in tokens]
    index = _skip_options(words, set())
    if index >= len(words) or words[index] not in IP_OBJECTS:
        return False
    return all(word not in IP_WRITE for word in words[index + 1:])


def _journalctl_readonly(tokens):
    for token in (_unquote_word(item) for item in tokens):
        if _VACUUM_RE.match(token) or token in ("--rotate", "--flush", "--relinquish-var"):
            return False
    return True


def _systemctl_readonly(tokens):
    words = [_unquote_word(token) for token in tokens]
    index = _skip_options(words, SYSTEMCTL_ARG)
    return index < len(words) and words[index] in SYSTEMCTL_OK


def _container_readonly(tokens):
    words = [_unquote_word(token) for token in tokens]
    index = _skip_options(words, set(["-H", "--host", "-c", "--context", "-l", "--log-level"]))
    if index >= len(words):
        return False
    sub = words[index]
    if sub in DOCKER_DIRECT:
        return True
    if sub == "container":
        return index + 1 < len(words) and words[index + 1] in ("ps", "ls", "logs", "inspect", "stats", "top", "port", "diff")
    if sub == "image":
        return index + 1 < len(words) and words[index + 1] in ("ls", "inspect")
    return False


def _kubectl_readonly(tokens):
    words = [_unquote_word(token) for token in tokens]
    index = _skip_options(words, KUBE_ARG)
    return index < len(words) and words[index] in KUBE_OK


def _curl_readonly(tokens):
    words = [_unquote_word(token) for token in tokens]
    i = 0
    while i < len(words):
        token = words[i]
        if token == "--":
            i += 1
            continue
        if token in ("-o", "-O", "--output", "--remote-name", "--remote-name-all") or token.startswith("--output="):
            return False
        if token in ("-d", "-F", "--form", "--form-string", "-T", "--upload-file", "-I", "--head") or token.startswith("--data") or token.startswith("--form=") or token.startswith("--upload-file="):
            return False
        if token.startswith("-") and not token.startswith("--"):
            cluster = token[1:]
            if any(ch in cluster for ch in "oOdFTI"):
                return False
            if "X" in cluster:
                attached = cluster[cluster.find("X") + 1:]
                method = attached or (words[i + 1] if i + 1 < len(words) else "")
                if not attached:
                    i += 1
                if method.upper() != "GET":
                    return False
            i += 1
            continue
        if token in ("-X", "--request") or token.startswith("--request="):
            if token.startswith("--request="):
                method = token[len("--request="):]
            else:
                i += 1
                method = words[i] if i < len(words) else ""
            if method.upper() != "GET":
                return False
        name = token.split("=", 1)[0]
        if name in CURL_ARG and "=" not in token:
            i += 1
        i += 1
    return True


def _args_are_readonly(name, arg_tokens):
    if name == "sed":
        return not _sed_writes(arg_tokens)
    if name == "sort":
        return not _sort_writes(arg_tokens)
    if name == "date":
        return not _date_writes(arg_tokens)
    if name in ("awk", "gawk"):
        return not _awk_writes(arg_tokens)
    if name == "find":
        return not _find_writes(arg_tokens)
    if name == "ip":
        return _ip_readonly(arg_tokens)
    if name == "journalctl":
        return _journalctl_readonly(arg_tokens)
    if name == "systemctl":
        return _systemctl_readonly(arg_tokens)
    if name in ("docker", "podman"):
        return _container_readonly(arg_tokens)
    if name == "kubectl":
        return _kubectl_readonly(arg_tokens)
    if name == "curl":
        return _curl_readonly(arg_tokens)
    return True


def _evaluate_pipeline(inner):
    text = str(inner or "")
    if _has_unsafe_redirect(text):
        return {"ok": False, "reason": "内部有输出重定向，会写文件"}
    segments = _split_shell_segments(text)
    if not segments:
        return {"ok": False, "reason": "内部结构无法静态确认"}
    saw_command = False
    for segment in segments:
        tokens = _shell_words(segment)
        if not tokens:
            continue
        if _is_assignment(_unquote_word(tokens[0])):
            return {"ok": False, "reason": "内部有前导环境变量赋值，不能自动放行"}
        name = _trusted_readonly_name(tokens[0])
        if not name:
            shown = _unquote_word(tokens[0]).lstrip("(").rstrip(")") or tokens[0]
            return {"ok": False, "reason": "内部命令 “%s” 不在只读白名单内" % shown}
        saw_command = True
        if not _args_are_readonly(name, tokens[1:]):
            return {"ok": False, "reason": "内部 %s 带了会改系统或写文件的参数" % name}
    if not saw_command:
        return {"ok": False, "reason": "内部结构无法静态确认"}
    return {"ok": True, "reason": "内部仅调用只读命令"}


def _object_in(source):
    source = str(source or "")
    found = re.search(r"\bof\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|(\S+))", source, re.I)
    if found:
        value = (found.group(1) or found.group(2) or found.group(3) or "").rstrip(");")
        if value and value != "/dev/null":
            return value
    redir = re.search(r"(?:&>>|&>|>>|(?<!&)>)\s*(?:\"([^\"]+)\"|'([^']+)'|(/[^\s;&|]+))", source)
    if redir:
        target = redir.group(1) or redir.group(2) or redir.group(3)
        if target and target != "/dev/null":
            return target
    paths = [
        item.group(1)
        for item in re.finditer(r"(?:^|[\s=])(/(?:[\w.+@=-]+/)*[\w.+@=-]+)", source)
        if item.group(1) != "/dev/null"
    ]
    return paths[-1] if paths else None


def _extract_target(text, finding):
    match = str(finding.get("match") or "")
    found = _object_in(match)
    if found:
        return found
    start = max(0, finding.get("index") or 0)
    line_end = text.find("\n", start)
    if line_end < 0:
        line = text[start:min(len(text), start + len(match) + 160)]
    else:
        line = text[start:line_end]
    return _object_in(line)


def _annotate_finding(text, finding):
    finding["target"] = _extract_target(text, finding)
    finding["impact"] = _impact_for(finding.get("category"))
    return finding


def analyze_command(text, depth=0):
    """返回 {category, findings, substitutions, autoApproved}。"""
    raw = str(text or "")
    if depth > 8:
        finding = _annotate_finding(raw, {
            "tier": "dynamic",
            "category": "动态变量或命令替换执行",
            "match": raw[:120],
            "index": 0,
            "reason": "嵌套过深，无法静态确认",
        })
        return {"category": finding["category"], "findings": [finding], "substitutions": [], "autoApproved": []}
    normalized = re.sub(r"\\\r?\n", " ", raw)
    scanned = _scan_shell(normalized)
    findings = _hard_findings(normalized, scanned["blanked"])
    findings.extend(_db_client_findings(normalized))
    pipe = PIPE_TO_SHELL.search(scanned["blanked"])
    if pipe:
        _push_finding(findings, {
            "tier": "dynamic",
            "category": "将编码或下载内容交给命令解释器执行",
            "match": normalized[pipe.start():pipe.end()][:200],
            "index": pipe.start(),
            "reason": "命中把内容交给解释器执行的写法",
        })
    for pattern in DYNAMIC_ONLY:
        match = pattern.search(scanned["blanked"])
        if match:
            _push_finding(findings, {
                "tier": "dynamic",
                "category": "动态变量或命令替换执行",
                "match": normalized[match.start():match.end()],
                "index": match.start(),
                "reason": "命中 eval/source 或点号执行",
            })
    substitutions = []
    for entry in scanned["substitutions"]:
        nested = analyze_command(entry["inner"], depth + 1)
        nested_hard = next((item for item in nested["findings"] if item["tier"] == "hard"), None)
        item = dict(entry)
        if nested_hard:
            base = nested_hard["category"].replace("（命令替换内部）", "")
            item["verdict"] = "blocked"
            item["nestedCategory"] = base
            item["reason"] = "命令替换内部命中高危规则：" + base
        else:
            verdict = _evaluate_pipeline(entry["inner"])
            if not verdict["ok"] or nested["findings"]:
                item["verdict"] = "blocked"
                item["reason"] = "内部还有无法自动放行的命中" if verdict["ok"] else verdict["reason"]
            else:
                item["verdict"] = "readonly"
                item["reason"] = verdict["reason"]
        substitutions.append(item)
    for substitution in substitutions:
        if substitution["verdict"] != "blocked":
            continue
        base = substitution.get("nestedCategory")
        _push_finding(findings, {
            "tier": "hard" if base else "dynamic",
            "category": (base + "（命令替换内部）") if base else "动态变量或命令替换执行",
            "match": substitution["raw"],
            "index": substitution["index"],
            "reason": substitution["reason"],
        })
    masked = _mask_substitutions(normalized, substitutions)
    findings.extend(_interpreter_findings(normalized, masked, depth))
    findings.extend(_command_position_findings(normalized, masked, substitutions))
    findings.sort(key=lambda finding: (finding["index"], finding["category"]))
    seen = set()
    unique = []
    for finding in findings:
        key = (finding["tier"], finding["category"], finding["index"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(_annotate_finding(normalized, finding))
    hard = next((item for item in unique if item["tier"] == "hard"), None)
    return {
        "category": hard["category"] if hard else (unique[0]["category"] if unique else None),
        "findings": unique,
        "substitutions": substitutions,
        "autoApproved": [item for item in substitutions if item["verdict"] == "readonly"],
    }


def _collect_review(job, analysis):
    review = job.get("safetyReview") or {}
    review_findings = list(review.get("findings") or [])
    local_findings = list((analysis or {}).get("findings") or [])
    findings = local_findings if len(local_findings) > len(review_findings) else (review_findings or local_findings)
    auto = list(review.get("autoApproved") or [])
    local_auto = list((analysis or {}).get("autoApproved") or [])
    if len(local_auto) > len(auto):
        auto = local_auto
    elif not auto:
        auto = local_auto
    total = review.get("totalFindings")
    if not isinstance(total, int) or total < len(findings):
        total = len(findings)
    return findings, auto, total


def _escape_controls(text):
    out = []
    for ch in text:
        code = ord(ch)
        if ch in "\n\t":
            out.append(ch)
            continue
        if code < 32 or code == 127 or 128 <= code <= 159 or 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069:
            out.append("\\u%04x" % code)
            continue
        out.append(ch)
    return "".join(out)


def _clip(text, limit):
    text = str(text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _snippet(finding):
    if finding.get("snippet"):
        return str(finding.get("snippet")).replace("\r", " ").replace("\n", " ")[:160]
    return str(finding.get("match") or "").lstrip("\r\n").replace("\r", " ").replace("\n", " ")[:160]


def _highlight_spans(text, findings):
    spans = []
    for finding in findings:
        raw = str(finding.get("match") or "")
        index = finding.get("index")
        if not raw or not isinstance(index, int) or index < 0:
            continue
        if text[index:index + len(raw)] != raw:
            continue
        spans.append((index, index + len(raw)))
    spans.sort(reverse=True)
    last_start = None
    for start, end in spans:
        if last_start is not None and end > last_start:
            continue
        text = text[:start] + "【" + text[start:end] + "】" + text[end:]
        last_start = start
    return text


def _excerpt(marked):
    lines = marked.split("\n")
    hot = set()
    for index, line in enumerate(lines):
        if "【" in line or "】" in line:
            if index:
                hot.add(index - 1)
            hot.add(index)
            if index + 1 < len(lines):
                hot.add(index + 1)
    if not hot:
        chosen = lines[:2]
        body = "\n".join(_trim_line(line) for line in chosen)
        omitted = len(lines) - len(chosen)
        if omitted > 0:
            body += "\n…（其余 %d 行未展开）" % omitted
        return body
    parts = []
    last = -2
    for index in sorted(hot):
        if last >= 0 and index > last + 1:
            parts.append("…")
        parts.append(_trim_line(lines[index]))
        last = index
    if len(parts) > 8:
        parts = parts[:8] + ["…（其余命中行未展开）"]
    return "\n".join(parts)


def _trim_line(line):
    if len(line) > 180:
        return line[:180] + "…"
    return line


def _fit_message(text):
    if len(text) <= DIALOG_CHAR_BUDGET and text.count("\n") + 1 <= DIALOG_LINE_BUDGET:
        return text
    start = text.find("\n---\n")
    end = text.rfind("\n---\n")
    if start < 0 or end <= start:
        return text[:DIALOG_CHAR_BUDGET]
    head = text[:start + 5]
    foot = text[end:]
    room = DIALOG_CHAR_BUDGET - len(head) - len(foot) - 20
    body = text[start + 5:end]
    if room < 40:
        room = 40
    if len(body) > room:
        body = body[:room] + "\n…（命令摘录已截断）"
    fitted = head + body + foot
    lines = fitted.split("\n")
    if len(lines) > DIALOG_LINE_BUDGET:
        # 保留结尾说明，只压缩命令摘录。
        overflow = len(lines) - DIALOG_LINE_BUDGET
        body_lines = body.split("\n")
        keep = max(1, len(body_lines) - overflow)
        body = "\n".join(body_lines[:keep] + ["…（命令摘录已截断）"])
        fitted = head + body + foot
    return fitted


def approval_message(job, analysis=None):
    action = job.get("action", {})
    findings, auto, total = _collect_review(job, analysis)
    meta = metadata()
    remote_address = str(meta.get("remoteAddress") or "未知主机")
    session_path = str(meta.get("sessionPath") or "")
    host_line = "目标主机：" + remote_address
    if session_path:
        host_line += "　会话：" + session_path
    if action.get("type") == "send":
        operation = "发送终端输入" + ("并按回车" if action.get("enter", False) else "（不按回车）")
        raw_input = str(action.get("text", ""))
        shown_findings = findings[:DIALOG_FINDING_LIMIT]
        marked = _highlight_spans(raw_input, shown_findings) if shown_findings else raw_input
        shown_input = _escape_controls(_excerpt(marked))
    else:
        operation = "发送 Ctrl+C 中断当前命令"
        shown_input = "Ctrl+C"
        shown_findings = []
    header = ["AI Agent 请求执行一个终端操作。", ""]
    if findings:
        header.append("⚠ 需要你重点确认：" + str(total) + " 处")
        header.append("────────────────────────────")
        for order, finding in enumerate(shown_findings, 1):
            header.append("%d) 规则：%s" % (order, finding.get("category")))
            header.append("   片段：" + _snippet(finding))
            target = finding.get("target")
            if target:
                header.append("   对象：" + str(target))
            impact = finding.get("impact") or _impact_for(finding.get("category"))
            header.append("   后果：" + str(impact))
        if total > len(shown_findings):
            header.append("…… 另有 %d 处" % (total - len(shown_findings)))
        header.append("────────────────────────────")
        if auto:
            header.append("另有 %d 处命令替换未单独列入上表。" % len(auto))
        header.append("")
    elif auto:
        header.append("命令含 %d 处命令替换，解析后未发现需要重点确认的命中。" % len(auto))
        header.append("")
    command_label = "命令（【】内为需要确认的片段；长命令只展示命中行及其相邻一行）：" if action.get("type") == "send" else "输入："
    message = "\n".join(header) + "\n" + "\n".join([
        host_line,
        "Agent：" + str(job.get("agentId", "unknown-agent")),
        "操作：" + operation,
        "风险等级：" + RISK_LABELS.get(str(action.get("riskLevel", "")), "未说明"),
        "",
        "为什么要做：",
        _clip(action.get("explanation", ""), DIALOG_FIELD_LIMIT),
        "",
        "预期结果：",
        _clip(action.get("expectedOutcome", ""), DIALOG_FIELD_LIMIT),
        "",
        command_label,
        "---",
        shown_input,
        "---",
        "",
        "只有在你理解并同意以上内容时才点击“是”。点击“否”不会向服务器发送任何内容。",
    ])
    return _fit_message(message)


def request_user_approval(job, analysis=None):
    try:
        # Xshell MessageBox nType=4 displays Yes/No; return value 6 means Yes.
        return int(xsh.Dialog.MessageBox(approval_message(job, analysis), "Xshell Agent Bridge 安全确认", 4)) == 6
    except Exception as error:
        raise RuntimeError("无法显示 Xshell 安全确认框，已拒绝执行：" + str(error))


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
