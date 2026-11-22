// Command policy shared by the daemon. The Xshell script in
// xshell/xshell_agent_bridge.py must apply the same decisions: a normal-mode
// substitution is auto-approved only when both sides can prove it is read-only.

const DELETE_COMMANDS = new Set([
  'rm', 'rmdir', 'unlink', 'shred', 'remove-item', 'clear-content', 'erase', 'del', 'rd',
]);
const SHUTDOWN_COMMANDS = new Set(['shutdown', 'reboot', 'poweroff', 'halt']);
const DISK_COMMANDS = new Set(['wipefs', 'blkdiscard', 'fdisk', 'cfdisk', 'sfdisk', 'format-volume']);
const WRAPPERS = new Set(['sudo', 'command', 'env', 'xargs', 'nohup', 'time', 'nice', 'exec', 'builtin']);
const WRAPPER_ARG_OPTIONS = {
  sudo: new Set(['-u', '-g', '-p', '-h', '-C', '-D', '-T', '-R', '-U', '--user', '--group', '--prompt', '--host', '--chdir', '--role', '--other-user', '--close-from', '--command-timeout']),
  command: new Set(),
  env: new Set(['-u', '-C', '-S', '--unset', '--chdir', '--split-string', '--default-signal', '--ignore-signal', '--block-signal', '--argv0']),
  xargs: new Set(['-a', '-d', '-E', '-I', '-J', '-L', '-l', '-n', '-P', '-s', '--arg-file', '--delimiter', '--eof', '--replace', '--max-lines', '--max-args', '--max-procs', '--max-chars']),
  nohup: new Set(),
  time: new Set(['-f', '-o', '--format', '--output']),
  nice: new Set(['-n', '--adjustment']),
  exec: new Set(['-a']),
  builtin: new Set(),
};
const BARE_READONLY = new Set([
  'cat', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'awk', 'gawk', 'sed', 'cut', 'tr',
  'sort', 'uniq', 'wc', 'ls', 'df', 'du', 'free', 'ps', 'pgrep', 'pidof',
  'pwd', 'whoami', 'id', 'uname', 'date', 'stat', 'readlink', 'realpath',
  'basename', 'dirname', 'echo', 'printf', 'test', 'expr', 'true', 'false', 'seq',
  'column', 'lsblk', 'lscpu', 'nproc', 'uptime', 'which', 'type', 'printenv', 'find',
  'hostname', 'ss', 'jq', 'vmstat', 'iostat',
]);
const RESTRICTED_READONLY = new Set(['ip', 'journalctl', 'systemctl', 'docker', 'podman', 'kubectl', 'curl']);
const INTERPRETERS = new Set([
  'sh', 'bash', 'python', 'python3', 'node', 'perl', 'ruby', 'php', 'lua', 'pwsh', 'powershell', 'cmd', 'cmd.exe',
]);
const VERSION_FLAGS = new Set(['--version', '-V', '-v']);
const IP_OBJECTS = new Set(['show', 'list', 'a', 'r', 'addr', 'address', 'route', 'link']);
const IP_WRITE = new Set(['add', 'del', 'delete', 'set', 'change', 'replace', 'flush']);
const SYSTEMCTL_OK = new Set(['status', 'show', 'is-active', 'is-enabled', 'is-failed', 'list-units', 'list-unit-files', 'cat']);
const SYSTEMCTL_ARG = new Set(['-t', '--type', '-p', '--property', '--state', '-o', '--output', '--root']);
const DOCKER_DIRECT = new Set(['ps', 'images', 'logs', 'inspect', 'stats', 'top', 'info', 'version', 'port', 'diff']);
const KUBE_OK = new Set(['get', 'describe', 'logs', 'top', 'version', 'cluster-info', 'api-resources']);
const KUBE_ARG = new Set(['-n', '--namespace', '--context', '--kubeconfig', '-o', '--output', '-l', '--selector', '--field-selector', '--sort-by', '--cluster']);
const CURL_ARG = new Set(['-H', '--header', '-A', '--user-agent', '-e', '--referer', '-b', '--cookie', '--connect-timeout', '-m', '--max-time', '--retry', '--retry-delay', '-u', '--user', '--proxy']);

const PIPE_TO_SHELL = /\b(?:base64|openssl\s+enc|xxd\s+-r|curl|wget)\b[^\r\n]{0,1000}\|\s*(?:(?:sudo|env|command|nohup)\s+)*(?:\/(?:usr\/)?bin\/)?(?:ba)?sh\b/i;
const SCRIPT_DELETE = /\b(?:os\.(?:remove|unlink)|shutil\.rmtree|fileutils\.rm_rf|fs\.(?:rm|unlink)(?:sync)?|[a-z_$][\w$]*\.unlink)\s*\(/i;
const SQL_PATTERN = /(?:^|[\s;"'`])(?:drop\s+(?:database|schema|table|view|index|user)|truncate\s+(?:table\s+)?|delete\s+from)\b/i;
const DYNAMIC_ONLY = [
  /(?:^|[\r\n;&|]\s*)(?:eval|source)\b/i,
  /(?:^|[\r\n;&|]\s*)\.\s+/i,
];

const IMPACTS = [
  ['文件删除或内容清空', '会删除文件或清空文件内容'],
  ['脚本删除文件', '会在脚本里删除文件'],
  ['find 批量删除', '会按条件批量删除文件或执行命令'],
  ['容器或编排资源删除', '会删除容器、镜像或编排资源'],
  ['数据库删除或清空', '会删除或清空数据库里的对象'],
  ['磁盘格式化或擦除', '会格式化或擦除磁盘上的数据'],
  ['软件包卸载', '会卸载系统里的软件包'],
  ['版本库强制清理', '会强制丢掉版本库里尚未提交的内容'],
  ['关机或重启', '会关闭或重新启动这台机器'],
  ['防火墙规则清空', '会清空防火墙规则'],
  ['将编码或下载内容交给命令解释器执行', '会把下载或编码后的内容当作命令执行'],
  ['命令解释器或脚本解释器执行', '会启动解释器执行一段代码'],
  ['动态变量或命令替换执行', '实际要执行的命令在发送前无法确定'],
];

function impactFor(category) {
  const raw = String(category || '');
  const base = raw.replace(/（命令替换内部）/g, '');
  const sentence = IMPACTS.find(([name]) => base.startsWith(name));
  const text = sentence ? sentence[1] : '需要你确认这段命令会做什么';
  return raw.includes('（命令替换内部）') ? text + '（发生在命令替换内部）' : text;
}

function unquoteWord(token) {
  let out = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < token.length; i += 1) {
    const ch = token[i];
    if (inSingle) {
      if (ch === "'") inSingle = false;
      else out += ch;
      continue;
    }
    if (inDouble) {
      if (ch === '\\' && i + 1 < token.length) {
        out += token[i + 1];
        i += 1;
        continue;
      }
      if (ch === '"') inDouble = false;
      else out += ch;
      continue;
    }
    if (ch === '\\' && i + 1 < token.length) {
      out += token[i + 1];
      i += 1;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      continue;
    }
    out += ch;
  }
  return out;
}

function isAssignment(word) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(word);
}

function isVariableWord(word) {
  return /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(word) || /^\$\{[^}]+\}$/.test(word);
}

function shellWords(segment) {
  const words = [];
  let buf = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < segment.length; i += 1) {
    const ch = segment[i];
    if (inSingle) {
      buf += ch;
      if (ch === "'") inSingle = false;
      continue;
    }
    if (ch === '\\') {
      buf += segment.slice(i, Math.min(segment.length, i + 2));
      i += 1;
      continue;
    }
    if (ch === '"') {
      inDouble = !inDouble;
      buf += ch;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = true;
      buf += ch;
      continue;
    }
    if (!inDouble && /\s/.test(ch)) {
      if (buf) words.push(buf);
      buf = '';
      continue;
    }
    buf += ch;
  }
  if (buf) words.push(buf);
  return words;
}

function tokenOffsets(segment, tokens) {
  const offsets = [];
  let cursor = 0;
  for (const token of tokens) {
    const at = segment.indexOf(token, cursor);
    offsets.push(at < 0 ? cursor : at);
    cursor = (at < 0 ? cursor : at) + token.length;
  }
  return offsets;
}

// Split on shell separators. `&` is not a separator when it belongs to `&>` / `>&`.
export function splitShellSegments(text) {
  const segments = [];
  let buffer = '';
  let inSingle = false;
  let inDouble = false;
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (inSingle) {
      buffer += ch;
      if (ch === "'") inSingle = false;
      i += 1;
      continue;
    }
    if (ch === '\\') {
      buffer += text.slice(i, Math.min(text.length, i + 2));
      i += 2;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = true;
      buffer += ch;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inDouble = !inDouble;
      buffer += ch;
      i += 1;
      continue;
    }
    if (!inDouble && (ch === ';' || ch === '\n' || ch === '|' || ch === '&')) {
      if (ch === '&' && (text[i + 1] === '>' || buffer.endsWith('>'))) {
        buffer += ch;
        i += 1;
        continue;
      }
      if (buffer.trim()) segments.push(buffer);
      buffer = '';
      while (i < text.length && ';|&\n'.includes(text[i])) i += 1;
      continue;
    }
    buffer += ch;
    i += 1;
  }
  if (buffer.trim()) segments.push(buffer);
  return segments;
}

function matchHeredoc(text, i) {
  if (text[i] !== '<' || text[i + 1] !== '<' || text[i + 2] === '<') return null;
  let j = i + 2;
  let stripTabs = false;
  if (text[j] === '-') {
    stripTabs = true;
    j += 1;
  }
  while (j < text.length && (text[j] === ' ' || text[j] === '\t')) j += 1;
  if (j >= text.length || text[j] === '\n' || text[j] === ';') return null;
  let delim = '';
  let quoted = false;
  let inSingle = false;
  let inDouble = false;
  while (j < text.length) {
    const ch = text[j];
    if (inSingle) {
      if (ch === "'") inSingle = false;
      else delim += ch;
      j += 1;
      continue;
    }
    if (inDouble) {
      if (ch === '\\' && j + 1 < text.length) {
        delim += text[j + 1];
        j += 2;
        continue;
      }
      if (ch === '"') inDouble = false;
      else delim += ch;
      j += 1;
      continue;
    }
    if (ch === '\\' && j + 1 < text.length) {
      quoted = true;
      delim += text[j + 1];
      j += 2;
      continue;
    }
    if (ch === "'") {
      quoted = true;
      inSingle = true;
      j += 1;
      continue;
    }
    if (ch === '"') {
      quoted = true;
      inDouble = true;
      j += 1;
      continue;
    }
    if (' \t\n;&|<>'.includes(ch)) break;
    delim += ch;
    j += 1;
  }
  if (!delim || inSingle || inDouble) return null;
  return { delim, quoted, stripTabs, end: j };
}

function lineIsDelim(line, heredoc) {
  const compare = heredoc.stripTabs ? line.replace(/^\t+/, '') : line;
  return compare === heredoc.delim;
}

function readCommandSubstitution(text, start) {
  let depth = 1;
  let j = start + 2;
  let single = false;
  let double = false;
  while (j < text.length && depth > 0) {
    const ch = text[j];
    if (single) {
      if (ch === "'") single = false;
      j += 1;
      continue;
    }
    if (ch === '\\') {
      j += 2;
      continue;
    }
    if (ch === "'" && !double) {
      single = true;
      j += 1;
      continue;
    }
    if (ch === '"') {
      double = !double;
      j += 1;
      continue;
    }
    if (!double && ch === '(') depth += 1;
    else if (!double && ch === ')') depth -= 1;
    j += 1;
  }
  const end = depth === 0 ? j : text.length;
  return {
    kind: 'command',
    raw: text.slice(start, end),
    inner: text.slice(start + 2, Math.max(start + 2, end - (depth === 0 ? 1 : 0))),
    index: start,
    end,
  };
}

function readBacktick(text, start) {
  let j = start + 1;
  while (j < text.length) {
    if (text[j] === '\\') {
      j += 2;
      continue;
    }
    if (text[j] === '`') {
      j += 1;
      break;
    }
    j += 1;
  }
  const closed = j > start + 1 && text[j - 1] === '`';
  return {
    kind: 'backtick',
    raw: text.slice(start, j),
    inner: text.slice(start + 1, closed ? j - 1 : j),
    index: start,
    end: j,
  };
}

// One walk so quote, comment, heredoc, and substitution rules cannot drift.
function scanShell(text) {
  const substitutions = [];
  const blanked = text.split('');
  const pending = [];
  let heredoc = null;
  let inSingle = false;
  let inDouble = false;
  let inComment = false;
  let lineStart = 0;
  let i = 0;
  const blank = (from, to) => {
    const end = Math.min(to, blanked.length);
    for (let k = Math.max(0, from); k < end; k += 1) {
      if (text[k] !== '\n') blanked[k] = ' ';
    }
  };
  const startPendingBody = () => {
    if (!heredoc && pending.length) heredoc = pending.shift();
  };

  while (i < text.length) {
    if (heredoc && (heredoc.quoted || i === lineStart)) {
      const nl = text.indexOf('\n', i);
      const lineEnd = nl === -1 ? text.length : nl;
      const line = text.slice(i, lineEnd);
      if (i === lineStart && lineIsDelim(line, heredoc)) {
        blank(i, lineEnd);
        heredoc = null;
        i = nl === -1 ? text.length : nl + 1;
        lineStart = i;
        startPendingBody();
        continue;
      }
      if (heredoc.quoted) {
        blank(i, lineEnd);
        i = nl === -1 ? text.length : nl + 1;
        lineStart = i;
        continue;
      }
    }

    const ch = text[i];
    if (ch === '\n') {
      inComment = false;
      i += 1;
      lineStart = i;
      if (!inSingle && !inDouble) startPendingBody();
      continue;
    }
    if (inComment) {
      blanked[i] = ' ';
      i += 1;
      continue;
    }
    if (inSingle) {
      blanked[i] = ' ';
      if (ch === "'") inSingle = false;
      i += 1;
      continue;
    }
    if (ch === '\\') {
      if (!inDouble && !heredoc && text[i + 1] === '\n') {
        blanked[i] = ' ';
        i += 1;
        continue;
      }
      const next = Math.min(text.length, i + 2);
      if (inDouble || heredoc) blank(i, next);
      i = next;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = true;
      blanked[i] = ' ';
      i += 1;
      continue;
    }
    if (ch === '"') {
      inDouble = !inDouble;
      blanked[i] = ' ';
      i += 1;
      continue;
    }
    if (inDouble) {
      if (ch === '$' && text[i + 1] === '(' && text[i + 2] === '(') {
        blank(i, i + 3);
        i += 3;
        continue;
      }
      if (ch === '$' && text[i + 1] === '(') {
        const sub = readCommandSubstitution(text, i);
        substitutions.push(sub);
        blank(sub.index, sub.end);
        i = sub.end;
        continue;
      }
      if (ch === '`') {
        const sub = readBacktick(text, i);
        substitutions.push(sub);
        blank(sub.index, sub.end);
        i = sub.end;
        continue;
      }
      blanked[i] = ' ';
      i += 1;
      continue;
    }
    if (ch === '#') {
      inComment = true;
      blanked[i] = ' ';
      i += 1;
      continue;
    }
    if (!heredoc) {
      const opener = matchHeredoc(text, i);
      if (opener) {
        pending.push(opener);
        i = opener.end;
        continue;
      }
    }
    if (ch === '$' && text[i + 1] === '(') {
      if (text[i + 2] === '(') {
        i += 3;
        continue;
      }
      const sub = readCommandSubstitution(text, i);
      substitutions.push(sub);
      blank(sub.index, sub.end);
      i = sub.end;
      continue;
    }
    if (ch === '`') {
      const sub = readBacktick(text, i);
      substitutions.push(sub);
      blank(sub.index, sub.end);
      i = sub.end;
      continue;
    }
    if (heredoc && !heredoc.quoted) blanked[i] = ' ';
    i += 1;
  }
  return { substitutions, blanked: blanked.join('') };
}

function maskSubstitutions(text, substitutions) {
  let masked = text;
  const ordered = [...substitutions].sort((a, b) => b.index - a.index);
  for (const entry of ordered) {
    masked = masked.slice(0, entry.index) + '\u0001'.repeat(entry.raw.length) + masked.slice(entry.index + entry.raw.length);
  }
  return masked;
}

function basenameOf(word) {
  const slash = Math.max(word.lastIndexOf('/'), word.lastIndexOf('\\'));
  return (slash >= 0 ? word.slice(slash + 1) : word).toLowerCase();
}

function normalizeCommandBase(token) {
  let word = unquoteWord(token).replace(/^\(+/, '').replace(/\)+$/, '');
  if (!word || word.includes('\u0001')) return '';
  return basenameOf(word);
}

function isTrustedCommandToken(token) {
  const word = unquoteWord(token).replace(/^\(+/, '').replace(/\)+$/, '');
  if (!word || word.includes('\u0001')) return false;
  if (!word.includes('/') && !word.includes('\\')) return true;
  if (word.startsWith('/bin/') && !word.slice(5).includes('/')) return true;
  if (word.startsWith('/usr/bin/') && !word.slice(9).includes('/')) return true;
  return false;
}

function trustedReadonlyName(token) {
  if (!isTrustedCommandToken(token)) return null;
  const base = normalizeCommandBase(token);
  if (BARE_READONLY.has(base) || RESTRICTED_READONLY.has(base)) return base;
  return null;
}

function resolveInvocation(tokens) {
  let i = 0;
  let leadingAssign = false;
  while (i < tokens.length && isAssignment(unquoteWord(tokens[i]))) {
    leadingAssign = true;
    i += 1;
  }
  let envAssign = false;
  while (i < tokens.length) {
    const shown = unquoteWord(tokens[i]);
    if (shown.includes('\u0001')) {
      return { commandIndex: i, leadingAssign, envAssign, dynamic: true };
    }
    const name = basenameOf(shown.replace(/^\(+/, '').replace(/\)+$/, ''));
    if (!WRAPPERS.has(name)) return { commandIndex: i, leadingAssign, envAssign, dynamic: false };
    const argOpts = WRAPPER_ARG_OPTIONS[name] || new Set();
    i += 1;
    while (i < tokens.length) {
      const word = unquoteWord(tokens[i]);
      if (word.includes('\u0001')) return { commandIndex: i, leadingAssign, envAssign, dynamic: true };
      if (word === '--') {
        i += 1;
        break;
      }
      if (name === 'env' && isAssignment(word)) {
        envAssign = true;
        i += 1;
        continue;
      }
      if (word.startsWith('-')) {
        const opt = word.includes('=') ? word.split('=')[0] : word;
        if (!word.includes('=') && argOpts.has(opt)) {
          i += 2;
          continue;
        }
        i += 1;
        continue;
      }
      break;
    }
  }
  return { commandIndex: -1, leadingAssign, envAssign, dynamic: false };
}

function operands(words) {
  const out = [];
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    if (word === '--') {
      for (const rest of words.slice(i + 1)) {
        if (!rest.startsWith('-')) out.push(rest);
      }
      break;
    }
    if (word.startsWith('-')) continue;
    out.push(word);
  }
  return out;
}

function shortClusterHas(token, letter) {
  return token.startsWith('-') && !token.startsWith('--') && token.slice(1).includes(letter);
}

function classifyHard(base, argTokens) {
  const args = argTokens.join(' ');
  const ops = operands(argTokens);
  if (DELETE_COMMANDS.has(base)) return '文件删除或内容清空';
  if (SHUTDOWN_COMMANDS.has(base)) return '关机或重启';
  if (base === 'find' && /(?:^|\s)(?:-delete|-exec|-execdir|-ok|-okdir|-fprint\w*|-fls)\b/.test(args)) {
    return 'find 批量删除';
  }
  if (base === 'docker' || base === 'podman') {
    if (ops.includes('rm') || ops.includes('rmi') || ops.includes('prune')) return '容器或编排资源删除';
    if (ops.includes('compose') && ops.includes('down')) return '容器或编排资源删除';
  }
  if (base === 'kubectl' && ops.includes('delete')) return '容器或编排资源删除';
  if (base === 'helm' && ops.includes('uninstall')) return '容器或编排资源删除';
  if (base === 'crictl' && (ops.includes('rm') || ops.includes('rmi'))) return '容器或编排资源删除';
  if ((base === 'apt' || base === 'apt-get') && ops.some((word) => ['remove', 'purge', 'autoremove'].includes(word))) {
    return '软件包卸载';
  }
  if ((base === 'yum' || base === 'dnf') && ops.some((word) => ['remove', 'erase', 'autoremove'].includes(word))) {
    return '软件包卸载';
  }
  if (base === 'rpm' && argTokens.some((word) => word === '-e')) return '软件包卸载';
  if (base === 'apk' && ops.includes('del')) return '软件包卸载';
  if (base === 'pacman' && argTokens.some((word) => word.startsWith('-R'))) return '软件包卸载';
  if (DISK_COMMANDS.has(base) || base === 'mkfs' || base.startsWith('mkfs.')) return '磁盘格式化或擦除';
  if (base === 'dd' && /\bof\s*=\s*\/dev\//i.test(args)) return '磁盘格式化或擦除';
  if (base === 'git') {
    if (ops[0] === 'reset' && argTokens.some((word) => word === '--hard')) return '版本库强制清理';
    if (ops[0] === 'clean') {
      const force = argTokens.some((word) => word === '--force' || shortClusterHas(word, 'f'));
      if (force) return '版本库强制清理';
    }
  }
  if (base === 'systemctl' && ['poweroff', 'reboot', 'halt'].includes(ops[0])) return '关机或重启';
  if (base === 'init' && (argTokens[0] === '0' || argTokens[0] === '6')) return '关机或重启';
  if ((base === 'iptables' || base === 'ip6tables') && argTokens.some((word) => word === '-F' || word === '-X' || word === '--flush')) {
    return '防火墙规则清空';
  }
  if (base === 'nft' && ops[0] === 'flush' && ops[1] === 'ruleset') return '防火墙规则清空';
  return null;
}

function pushFinding(findings, finding) {
  findings.push({
    tier: finding.tier,
    category: finding.category,
    match: String(finding.match || '').slice(0, 240),
    index: finding.index,
    reason: finding.reason,
  });
}

function hardFindings(original, blanked) {
  const findings = [];
  let cursor = 0;
  for (const segment of splitShellSegments(blanked)) {
    const segmentStart = blanked.indexOf(segment, cursor);
    if (segmentStart < 0) continue;
    cursor = segmentStart + segment.length;
    const tokens = shellWords(segment);
    if (!tokens.length) continue;
    const offsets = tokenOffsets(segment, tokens);
    const resolved = resolveInvocation(tokens);
    if (resolved.commandIndex < 0 || resolved.dynamic) continue;
    const token = tokens[resolved.commandIndex];
    const base = normalizeCommandBase(token);
    if (!base) continue;
    const argTokens = tokens.slice(resolved.commandIndex + 1).map(unquoteWord).filter((word) => word && !word.includes('\u0001'));
    if (base === 'git') {
      const words = original.slice(segmentStart, cursor).trim().split(/\s+/);
      if (words[0] === 'git' && words[1] === 'clean'
          && words.slice(2).every((word) => /^-[dfnxX]+$/.test(word) || word === '--dry-run')
          && words.slice(2).some((word) => word === '--dry-run' || word.includes('n'))) continue;
    }
    const category = classifyHard(base, argTokens);
    if (!category) continue;
    const index = segmentStart + offsets[resolved.commandIndex];
    const end = segmentStart + offsets[tokens.length - 1] + tokens[tokens.length - 1].length;
    const match = original.slice(index, Math.min(original.length, Math.max(end, index + token.length), index + 200));
    pushFinding(findings, { tier: 'hard', category, match, index, reason: '命中高危命令特征' });
  }

  const script = SCRIPT_DELETE.exec(blanked);
  if (script) {
    pushFinding(findings, {
      tier: 'hard',
      category: '脚本删除文件',
      match: original.slice(script.index, script.index + script[0].length),
      index: script.index,
      reason: '命中高危命令特征',
    });
  }
  const sql = SQL_PATTERN.exec(blanked);
  if (sql) {
    pushFinding(findings, {
      tier: 'hard',
      category: '数据库删除或清空',
      match: original.slice(sql.index, sql.index + sql[0].length),
      index: sql.index,
      reason: '命中高危命令特征',
    });
  }
  return findings;
}

function dbClientFindings(original) {
  const findings = [];
  let cursor = 0;
  for (const segment of splitShellSegments(original)) {
    const segmentStart = original.indexOf(segment, cursor);
    if (segmentStart < 0) continue;
    cursor = segmentStart + segment.length;
    const tokens = shellWords(segment);
    const offsets = tokenOffsets(segment, tokens);
    const resolved = resolveInvocation(tokens);
    if (resolved.commandIndex < 0 || resolved.dynamic) continue;
    const base = normalizeCommandBase(tokens[resolved.commandIndex]);
    const flags = base === 'mysql' || base === 'mariadb' ? ['-e', '--execute'] : null;
    const psql = base === 'psql' ? ['-c', '--command'] : null;
    const names = flags || psql;
    if (!names) continue;
    const args = tokens.slice(resolved.commandIndex + 1);
    const argOffsets = offsets.slice(resolved.commandIndex + 1);
    for (let i = 0; i < args.length; i += 1) {
      const raw = args[i];
      const word = unquoteWord(raw);
      let sql = null;
      let sqlOffset = 0;
      if (names.includes(word) || names.some((name) => word === name)) {
        const next = args[i + 1];
        if (!next) continue;
        const parsed = parseQuoted(next);
        sql = parsed.quoted ? parsed.content : unquoteWord(next);
        sqlOffset = argOffsets[i + 1] + (parsed.quoted ? parsed.contentOffset : 0);
        i += 1;
      } else {
        const attached = names.find((name) => word.startsWith(name + '=') || (name.startsWith('-') && name.length === 2 && word.startsWith(name) && word.length > name.length));
        if (!attached) continue;
        if (word.startsWith(attached + '=')) sql = word.slice(attached.length + 1);
        else sql = word.slice(attached.length);
        const parsed = parseQuoted(sql);
        sql = parsed.quoted ? parsed.content : sql;
        sqlOffset = argOffsets[i] + raw.indexOf(sql);
        if (sqlOffset < argOffsets[i]) sqlOffset = argOffsets[i];
      }
      if (!sql || !SQL_PATTERN.test(sql)) continue;
      const index = segmentStart + sqlOffset;
      const match = original.slice(index, index + String(sql).length);
      pushFinding(findings, {
        tier: 'hard',
        category: '数据库删除或清空',
        match: match || sql,
        index,
        reason: '数据库客户端会执行引号里的删除语句',
      });
    }
  }
  return findings;
}

function parseQuoted(raw) {
  if (raw.length >= 2 && raw[0] === "'" && raw[raw.length - 1] === "'") {
    return { quoted: true, content: raw.slice(1, -1), contentOffset: 1, literal: true };
  }
  if (raw.length >= 2 && raw[0] === '"' && raw[raw.length - 1] === '"') {
    const body = raw.slice(1, -1);
    let out = '';
    for (let i = 0; i < body.length; i += 1) {
      if (body[i] === '\\' && i + 1 < body.length) {
        out += body[i + 1];
        i += 1;
        continue;
      }
      out += body[i];
    }
    return { quoted: true, content: out, contentOffset: 1, literal: out === body };
  }
  return { quoted: false, content: raw, contentOffset: 0, literal: false };
}

function extractDashC(rawTokens, baseOffsets, segmentStart) {
  for (let i = 0; i < rawTokens.length; i += 1) {
    const raw = rawTokens[i];
    if (raw.includes('\u0001')) return null;
    const word = unquoteWord(raw);
    if (word === '--') return null;
    if (!word.startsWith('-') || word.startsWith('--')) {
      if (word.startsWith('-')) continue;
      return null;
    }
    const marker = word.indexOf('c');
    if (marker < 0) continue;
    const afterRaw = raw.slice(raw.indexOf('c') + 1);
    if (afterRaw) {
      const parsed = parseQuoted(afterRaw);
      if (!parsed.quoted) return null;
      const contentAbs = segmentStart + baseOffsets[i] + raw.indexOf('c') + 1 + parsed.contentOffset;
      return { ...parsed, contentAbs };
    }
    const next = rawTokens[i + 1];
    if (!next) return null;
    const parsed = parseQuoted(next);
    if (!parsed.quoted) return null;
    return { ...parsed, contentAbs: segmentStart + baseOffsets[i + 1] + parsed.contentOffset };
  }
  return null;
}

function interpreterFindings(original, masked, depth) {
  const findings = [];
  let cursor = 0;
  for (const segment of splitShellSegments(masked)) {
    const segmentStart = masked.indexOf(segment, cursor);
    if (segmentStart < 0) continue;
    cursor = segmentStart + segment.length;
    const originalSegment = original.slice(segmentStart, segmentStart + segment.length);
    const tokens = shellWords(segment);
    if (!tokens.length) continue;
    const offsets = tokenOffsets(segment, tokens);
    const resolved = resolveInvocation(tokens);
    if (resolved.commandIndex < 0) continue;
    const cmdToken = tokens[resolved.commandIndex];
    const cmdWord = unquoteWord(cmdToken);
    if (cmdWord.includes('\u0001') || resolved.dynamic) continue;
    const base = normalizeCommandBase(cmdToken);
    if (!INTERPRETERS.has(base)) continue;
    const argTokens = tokens.slice(resolved.commandIndex + 1);
    const argOffsets = offsets.slice(resolved.commandIndex + 1);
    const rawArgs = argTokens.map((token, index) => originalSegment.slice(argOffsets[index], argOffsets[index] + token.length));
    const trusted = isTrustedCommandToken(cmdToken) && !resolved.leadingAssign && !resolved.envAssign;
    const versionOnly = trusted && rawArgs.length > 0 && rawArgs.every((token) => VERSION_FLAGS.has(unquoteWord(token)));
    if (versionOnly) continue;

    if (trusted && (base === 'sh' || base === 'bash')) {
      const script = extractDashC(rawArgs, argOffsets, segmentStart);
      if (script) {
        const inner = analyzeCommand(script.content, depth + 1);
        const plainScript = resolved.commandIndex === 0 && rawArgs.length === 2 && rawArgs[0] === '-c' && rawArgs[1].startsWith("'")
          && script.content.split('|').every((part) =>
            /^(?:pgrep|head|tail|wc|pwd|id|whoami|uname|hostname|ss)(?: +[A-Za-z0-9_./:-]+)*$/.test(part.trim()))
          && !/[\r\n]/.test(script.content);
        if (!inner.findings.length && plainScript && evaluatePipeline(script.content).ok) continue;
        const hoisted = [];
        if (script.literal) {
          for (const finding of inner.findings) {
            const index = script.contentAbs + finding.index;
            const match = String(finding.match || '');
            if (match && original.slice(index, index + match.length) === match) {
              hoisted.push({ ...finding, index });
            }
          }
        }
        if (hoisted.length) {
          findings.push(...hoisted);
          continue;
        }
      }
    }

    const index = segmentStart + offsets[resolved.commandIndex];
    const match = original.slice(index, index + cmdToken.length).slice(0, 200);
    pushFinding(findings, {
      tier: 'dynamic',
      category: '命令解释器或脚本解释器执行',
      match,
      index,
      reason: '命中把内容交给解释器执行的写法',
    });
  }
  return findings;
}

function commandPositionFindings(original, masked, substitutions) {
  const findings = [];
  let cursor = 0;
  for (const segment of splitShellSegments(masked)) {
    const segmentStart = masked.indexOf(segment, cursor);
    if (segmentStart < 0) continue;
    cursor = segmentStart + segment.length;
    const tokens = shellWords(segment);
    if (!tokens.length) continue;
    const offsets = tokenOffsets(segment, tokens);
    const resolved = resolveInvocation(tokens);
    if (resolved.commandIndex < 0) continue;
    const positions = [resolved.commandIndex];
    for (const pos of positions) {
      if (pos < 0 || pos >= tokens.length) continue;
      const token = tokens[pos];
      const index = segmentStart + offsets[pos];
      const match = original.slice(index, index + token.length);
      const covered = substitutions.some((entry) => entry.verdict === 'blocked' && entry.index === index);
      if (covered) continue;
      const word = unquoteWord(token);
      if (word.includes('\u0001') || match.includes('$(') || match.includes('`')) {
        pushFinding(findings, {
          tier: 'dynamic',
          category: '动态变量或命令替换执行',
          match: match.slice(0, 240),
          index,
          reason: '命令替换的结果被直接当作命令执行',
        });
      } else if (isVariableWord(word)) {
        pushFinding(findings, {
          tier: 'dynamic',
          category: '动态变量或命令替换执行',
          match: word.slice(0, 120),
          index,
          reason: '变量被当作命令执行，真正执行的命令静态不可知',
        });
      }
    }
  }
  return findings;
}

function readRedirectTarget(text, i) {
  while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i += 1;
  let target = '';
  let inSingle = false;
  let inDouble = false;
  while (i < text.length) {
    const ch = text[i];
    if (inSingle) {
      if (ch === "'") inSingle = false;
      else target += ch;
      i += 1;
      continue;
    }
    if (inDouble) {
      if (ch === '\\' && i + 1 < text.length) {
        target += text[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inDouble = false;
      else target += ch;
      i += 1;
      continue;
    }
    if (ch === '\\' && i + 1 < text.length) {
      target += text[i + 1];
      i += 2;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      i += 1;
      continue;
    }
    if (' \t\n;&|<>'.includes(ch)) break;
    target += ch;
    i += 1;
  }
  return { target, end: i };
}

function redirectAt(text, i) {
  if (text.startsWith('&>>', i)) {
    const target = readRedirectTarget(text, i + 3);
    return { safe: target.target === '/dev/null', next: target.end };
  }
  if (text.startsWith('&>', i)) {
    const target = readRedirectTarget(text, i + 2);
    return { safe: target.target === '/dev/null', next: target.end };
  }
  let j = i;
  while (j < text.length && text[j] >= '0' && text[j] <= '9') j += 1;
  const at = j;
  if (text.startsWith('>&', at)) {
    const target = readRedirectTarget(text, at + 2);
    if (/^\d+$/.test(target.target)) return { safe: true, next: target.end };
    return { safe: target.target === '/dev/null', next: target.end };
  }
  if (text.startsWith('>>', at)) {
    const target = readRedirectTarget(text, at + 2);
    return { safe: target.target === '/dev/null', next: target.end };
  }
  if (text[at] === '>') {
    const target = readRedirectTarget(text, at + 1);
    return { safe: target.target === '/dev/null', next: target.end };
  }
  return null;
}

function skipArithmetic(text, i) {
  let depth = 2;
  let inSingle = false;
  let inDouble = false;
  i += 3;
  while (i < text.length && depth > 0) {
    const ch = text[i];
    if (inSingle) {
      if (ch === "'") inSingle = false;
      i += 1;
      continue;
    }
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = true;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inDouble = !inDouble;
      i += 1;
      continue;
    }
    if (!inDouble && ch === '(') depth += 1;
    else if (!inDouble && ch === ')') depth -= 1;
    i += 1;
  }
  return i;
}

function hasUnsafeRedirect(text) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < text.length;) {
    const ch = text[i];
    if (inSingle) {
      if (ch === "'") inSingle = false;
      i += 1;
      continue;
    }
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = true;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inDouble = !inDouble;
      i += 1;
      continue;
    }
    if (inDouble) {
      i += 1;
      continue;
    }
    if (ch === '<' && text[i + 1] === '<') {
      i += 2;
      continue;
    }
    if (ch === '$' && text[i + 1] === '(' && text[i + 2] === '(') {
      i = skipArithmetic(text, i);
      continue;
    }
    const redirect = redirectAt(text, i);
    if (redirect) {
      if (!redirect.safe) return true;
      i = redirect.next > i ? redirect.next : i + 1;
      continue;
    }
    i += 1;
  }
  return false;
}

function skipSedAddress(script, i) {
  const skipOne = (k) => {
    if (k >= script.length) return k;
    if (script[k] === '$') return k + 1;
    if (script[k] >= '0' && script[k] <= '9') {
      let j = k;
      while (j < script.length && script[j] >= '0' && script[j] <= '9') j += 1;
      return j;
    }
    if (script[k] === '/' || script[k] === '\\') {
      const delim = script[k] === '\\' ? script[k + 1] : '/';
      if (!delim) return k;
      let j = k + (script[k] === '\\' ? 2 : 1);
      while (j < script.length && script[j] !== delim && script[j] !== '\n') {
        if (script[j] === '\\') j += 2;
        else j += 1;
      }
      if (script[j] === delim) j += 1;
      return j;
    }
    return k;
  };
  const next = skipOne(i);
  if (next === i) return i;
  if (script[next] === ',' || script[next] === '~') return skipOne(next + 1);
  return next;
}

function consumeTransform(script, i) {
  const delim = script[i + 1];
  if (!delim || /[\s;]/.test(delim)) return { index: i + 1, writes: false };
  let k = i + 2;
  const findDelim = () => {
    while (k < script.length) {
      if (script[k] === '\\' && k + 1 < script.length) {
        k += 2;
        continue;
      }
      if (script[k] === '\n') return false;
      if (script[k] === delim) {
        k += 1;
        return true;
      }
      k += 1;
    }
    return false;
  };
  if (!findDelim() || !findDelim()) return { index: Math.max(k, i + 1), writes: false };
  let flags = '';
  while (k < script.length && !/[\s;\n]/.test(script[k])) {
    flags += script[k];
    k += 1;
  }
  if (/[ewW]/.test(flags)) return { index: k, writes: true };
  if (/^[ \t]+[wWe](?:\s|;|$)/.test(script.slice(k))) return { index: k, writes: true };
  return { index: k, writes: false };
}

function sedScriptWrites(script) {
  let i = 0;
  while (i < script.length) {
    while (i < script.length && /[\s;]/.test(script[i])) i += 1;
    if (i >= script.length) return false;
    if (script[i] === '#') {
      while (i < script.length && script[i] !== '\n') i += 1;
      continue;
    }
    i = skipSedAddress(script, i);
    while (i < script.length && /[ \t]/.test(script[i])) i += 1;
    if (i < script.length && script[i] === '!') {
      i += 1;
      while (i < script.length && /[ \t]/.test(script[i])) i += 1;
    }
    if (i >= script.length) return false;
    const cmd = script[i];
    if (cmd === 'w' || cmd === 'W' || cmd === 'e') return true;
    if (cmd === 's' || cmd === 'y') {
      const parsed = consumeTransform(script, i);
      if (parsed.writes) return true;
      i = parsed.index;
      continue;
    }
    if (cmd === '{' || cmd === '}') {
      i += 1;
      continue;
    }
    if (cmd === ':') {
      i += 1;
      while (i < script.length && !/[\s;{}]/.test(script[i])) i += 1;
      continue;
    }
    if (cmd === 'a' || cmd === 'c' || cmd === 'i') {
      i += 1;
      while (i < script.length && script[i] !== '\n' && script[i] !== ';') i += 1;
      continue;
    }
    i += 1;
  }
  return false;
}

function sedWrites(tokens) {
  const words = tokens.map(unquoteWord);
  let sawScript = false;
  for (let i = 0; i < words.length; i += 1) {
    const token = words[i];
    if (token === '--') {
      if (!sawScript && words[i + 1] && sedScriptWrites(words[i + 1])) return true;
      break;
    }
    if (token === '--in-place' || token.startsWith('--in-place=') || token === '--file' || token.startsWith('--file=')) return true;
    if (token === '-e' || token === '--expression' || token.startsWith('--expression=')) {
      const script = token.startsWith('--expression=') ? token.slice('--expression='.length) : words[i + 1];
      if (!token.startsWith('--expression=')) i += 1;
      sawScript = true;
      if (script && sedScriptWrites(script)) return true;
      continue;
    }
    if (token.startsWith('--')) continue;
    if (token.startsWith('-') && token.length > 1) {
      for (let k = 1; k < token.length; k += 1) {
        const letter = token[k];
        if (letter === 'i' || letter === 'f') return true;
        if (letter === 'e') {
          const attached = token.slice(k + 1);
          const script = attached || words[i + 1];
          if (!attached) i += 1;
          sawScript = true;
          if (script && sedScriptWrites(script)) return true;
          break;
        }
      }
      continue;
    }
    if (!sawScript) {
      sawScript = true;
      if (sedScriptWrites(token)) return true;
    }
  }
  return false;
}

function sortWrites(tokens) {
  return tokens.map(unquoteWord).some((token) => token === '--output' || token.startsWith('--output=') || shortClusterHas(token, 'o'));
}

function dateWrites(tokens) {
  return tokens.map(unquoteWord).some((token) => {
    if (token.startsWith('+')) return false;
    return token === '--set' || token.startsWith('--set=') || shortClusterHas(token, 's');
  });
}

function awkProgramWrites(program) {
  if (/system\s*\(/.test(program)) return true;
  if (/\|\s*getline\b/.test(program)) return true;
  const noParens = program.replace(/\([^()]*\)/g, '');
  if (/\bprintf?\b[^;\n]*>>?\s*["'/]/.test(noParens)) return true;
  if (/\bprintf?\b[^;\n]*\|\s*["']/.test(noParens)) return true;
  return false;
}

function awkWrites(tokens) {
  const words = tokens.map(unquoteWord);
  let program = '';
  let sawProgram = false;
  for (let i = 0; i < words.length; i += 1) {
    const token = words[i];
    if (token === '--') {
      if (!sawProgram && words[i + 1]) program += `\n${words[i + 1]}`;
      break;
    }
    if (token === '-f' || token === '--file' || token.startsWith('--file=') || (token.startsWith('-f') && !token.startsWith('--'))) return true;
    if (token === '-e' || token === '--source' || token.startsWith('--source=') || (token.startsWith('-e') && token.length > 2 && !token.startsWith('--'))) {
      let src = words[i + 1] || '';
      if (token.startsWith('--source=')) src = token.slice('--source='.length);
      else if (token.startsWith('-e') && token.length > 2) src = token.slice(2);
      else i += 1;
      sawProgram = true;
      program += `\n${src}`;
      continue;
    }
    if (token.startsWith('-')) {
      if (!token.includes('=') && ['-v', '-F', '-W', '--field-separator', '--assign'].includes(token)) i += 1;
      continue;
    }
    if (!sawProgram) {
      sawProgram = true;
      program += `\n${token}`;
    }
  }
  return awkProgramWrites(program);
}

function findWrites(tokens) {
  return /(?:^|\s)(?:-delete|-exec|-execdir|-ok|-okdir|-fprint\w*|-fls)\b/.test(tokens.map(unquoteWord).join(' '));
}

function skipOptions(words, argOptions) {
  let i = 0;
  while (i < words.length && words[i].startsWith('-')) {
    const name = words[i].split('=')[0];
    if (!words[i].includes('=') && argOptions.has(name)) i += 2;
    else i += 1;
  }
  return i;
}

function ipReadonly(tokens) {
  const words = tokens.map(unquoteWord);
  const index = skipOptions(words, new Set());
  if (index >= words.length || !IP_OBJECTS.has(words[index])) return false;
  return words.slice(index + 1).every((word) => !IP_WRITE.has(word));
}

function journalctlReadonly(tokens) {
  return tokens.map(unquoteWord).every((token) => !/^--vacuum-/.test(token) && !['--rotate', '--flush', '--relinquish-var'].includes(token));
}

function systemctlReadonly(tokens) {
  const words = tokens.map(unquoteWord);
  const index = skipOptions(words, SYSTEMCTL_ARG);
  return index < words.length && SYSTEMCTL_OK.has(words[index]);
}

function containerReadonly(tokens) {
  const words = tokens.map(unquoteWord);
  const index = skipOptions(words, new Set(['-H', '--host', '-c', '--context', '-l', '--log-level']));
  if (index >= words.length) return false;
  const sub = words[index];
  if (DOCKER_DIRECT.has(sub)) return true;
  if (sub === 'container') return ['ps', 'ls', 'logs', 'inspect', 'stats', 'top', 'port', 'diff'].includes(words[index + 1]);
  if (sub === 'image') return ['ls', 'inspect'].includes(words[index + 1]);
  return false;
}

function kubectlReadonly(tokens) {
  const words = tokens.map(unquoteWord);
  const index = skipOptions(words, KUBE_ARG);
  return index < words.length && KUBE_OK.has(words[index]);
}

function curlReadonly(tokens) {
  const words = tokens.map(unquoteWord);
  for (let i = 0; i < words.length; i += 1) {
    const token = words[i];
    if (token === '--') continue;
    if (token === '-o' || token === '-O' || token === '--output' || token === '--remote-name' || token.startsWith('--output=') || token === '--remote-name-all') return false;
    if (token === '-d' || token.startsWith('--data') || token === '-F' || token === '--form' || token === '--form-string' || token.startsWith('--form=') || token === '-T' || token === '--upload-file' || token.startsWith('--upload-file=')) return false;
    if (token === '-I' || token === '--head') return false;
    if (token.startsWith('-') && !token.startsWith('--')) {
      const cluster = token.slice(1);
      if (/[oOdFTI]/.test(cluster)) return false;
      if (cluster.includes('X')) {
        const attached = cluster.slice(cluster.indexOf('X') + 1);
        const method = attached || words[i + 1] || '';
        if (!attached) i += 1;
        if (method.toUpperCase() !== 'GET') return false;
      }
      continue;
    }
    if (token === '-X' || token === '--request' || token.startsWith('--request=')) {
      const method = token.startsWith('--request=') ? token.slice('--request='.length) : (words[i + 1] || '');
      if (!token.startsWith('--request=')) i += 1;
      if (method.toUpperCase() !== 'GET') return false;
    }
    if (CURL_ARG.has(token.split('=')[0]) && !token.includes('=')) i += 1;
  }
  return true;
}

function argsAreReadonly(name, argTokens) {
  if (name === 'hostname') return argTokens.length === 0 || (argTokens.length === 1 && ['-I', '-i', '-f', '-s'].includes(argTokens[0]));
  if (name === 'ss') return argTokens.every((token) => /^-[alntup46]+$/.test(token));
  if (name === 'sed') return !sedWrites(argTokens);
  if (name === 'sort') return !sortWrites(argTokens);
  if (name === 'date') return !dateWrites(argTokens);
  if (name === 'awk' || name === 'gawk') return !awkWrites(argTokens);
  if (name === 'find') return !findWrites(argTokens);
  if (name === 'ip') return ipReadonly(argTokens);
  if (name === 'journalctl') return journalctlReadonly(argTokens);
  if (name === 'systemctl') return systemctlReadonly(argTokens);
  if (name === 'docker' || name === 'podman') return containerReadonly(argTokens);
  if (name === 'kubectl') return kubectlReadonly(argTokens);
  if (name === 'curl') return curlReadonly(argTokens);
  return true;
}

function evaluatePipeline(inner) {
  const text = String(inner || '');
  if (hasUnsafeRedirect(text)) return { ok: false, reason: '内部有输出重定向，会写文件' };
  const segments = splitShellSegments(text);
  if (!segments.length) return { ok: false, reason: '内部结构无法静态确认' };
  let sawCommand = false;
  for (const segment of segments) {
    const tokens = shellWords(segment);
    if (!tokens.length) continue;
    if (isAssignment(unquoteWord(tokens[0]))) {
      return { ok: false, reason: '内部有前导环境变量赋值，不能自动放行' };
    }
    const name = trustedReadonlyName(tokens[0]);
    if (!name) {
      const shown = unquoteWord(tokens[0]).replace(/^\(+/, '').replace(/\)+$/, '') || tokens[0];
      return { ok: false, reason: `内部命令 “${shown}” 不在只读白名单内` };
    }
    sawCommand = true;
    if (!argsAreReadonly(name, tokens.slice(1))) {
      return { ok: false, reason: `内部 ${name} 带了会改系统或写文件的参数` };
    }
  }
  if (!sawCommand) return { ok: false, reason: '内部结构无法静态确认' };
  return { ok: true, reason: '内部仅调用只读命令' };
}

function annotateFinding(text, finding) {
  const nested = /^\$\((rm [^()]+)\)$/.exec(finding.match);
  const words = shellWords(nested ? nested[1] : finding.match);
  const simpleDelete = finding.category.startsWith('文件删除或内容清空') && words[0] === 'rm'
    && finding.match.length < 200 && words.slice(1).every((word) => /^-[rRfidv]+$|^[./a-zA-Z0-9_][./a-zA-Z0-9_-]*$/.test(word));
  finding.target = simpleDelete ? words.slice(1).filter((word) => !word.startsWith('-')).join('、') || null : null;
  finding.impact = impactFor(finding.category);
  return finding;
}

export function analyzeCommand(text, depth = 0) {
  const raw = String(text || '');
  if (depth > 8) {
    const finding = annotateFinding(raw, {
      tier: 'dynamic',
      category: '动态变量或命令替换执行',
      match: raw.slice(0, 120),
      index: 0,
      reason: '嵌套过深，无法静态确认',
    });
    return { category: finding.category, findings: [finding], substitutions: [], autoApproved: [] };
  }
  const normalized = raw.replace(/\\\r?\n/g, ' ');
  const scanned = scanShell(normalized);
  const findings = hardFindings(normalized, scanned.blanked);
  findings.push(...dbClientFindings(normalized));

  const pipe = PIPE_TO_SHELL.exec(scanned.blanked);
  if (pipe) {
    pushFinding(findings, {
      tier: 'dynamic',
      category: '将编码或下载内容交给命令解释器执行',
      match: normalized.slice(pipe.index, pipe.index + pipe[0].length).slice(0, 200),
      index: pipe.index,
      reason: '命中把内容交给解释器执行的写法',
    });
  }
  for (const pattern of DYNAMIC_ONLY) {
    const match = pattern.exec(scanned.blanked);
    if (match) {
      pushFinding(findings, {
        tier: 'dynamic',
        category: '动态变量或命令替换执行',
        match: normalized.slice(match.index, match.index + match[0].length),
        index: match.index,
        reason: '命中 eval/source 或点号执行',
      });
    }
  }

  const substitutions = scanned.substitutions.map((entry) => {
    const nested = analyzeCommand(entry.inner, depth + 1);
    const nestedHard = nested.findings.find((finding) => finding.tier === 'hard');
    if (nestedHard) {
      const base = String(nestedHard.category).replace(/（命令替换内部）/g, '');
      return { ...entry, verdict: 'blocked', nestedCategory: base, reason: `命令替换内部命中高危规则：${base}` };
    }
    const verdict = evaluatePipeline(entry.inner);
    if (!verdict.ok || nested.findings.length) {
      return { ...entry, verdict: 'blocked', reason: verdict.ok ? '内部还有无法自动放行的命中' : verdict.reason };
    }
    return { ...entry, verdict: 'readonly', reason: verdict.reason };
  });

  for (const substitution of substitutions) {
    if (substitution.verdict !== 'blocked') continue;
    pushFinding(findings, {
      tier: substitution.nestedCategory ? 'hard' : 'dynamic',
      category: substitution.nestedCategory ? `${substitution.nestedCategory}（命令替换内部）` : '动态变量或命令替换执行',
      match: substitution.raw,
      index: substitution.index,
      reason: substitution.reason,
    });
  }

  const masked = maskSubstitutions(normalized, substitutions);
  findings.push(...interpreterFindings(normalized, masked, depth));
  findings.push(...commandPositionFindings(normalized, masked, substitutions));

  findings.sort((a, b) => a.index - b.index || (a.category < b.category ? -1 : a.category > b.category ? 1 : 0));
  const seen = new Set();
  const unique = findings.filter((finding) => {
    const key = `${finding.tier}\u0000${finding.category}\u0000${finding.index}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).map((finding) => annotateFinding(normalized, finding));

  const hard = unique.find((finding) => finding.tier === 'hard');
  return {
    category: hard ? hard.category : (unique[0]?.category || null),
    findings: unique,
    substitutions,
    autoApproved: substitutions.filter((entry) => entry.verdict === 'readonly'),
  };
}

export function buildSafetyReview(analysis) {
  if (!analysis) return null;
  const findings = analysis.findings || [];
  const autoApproved = analysis.autoApproved || [];
  if (!findings.length && !autoApproved.length) return null;
  return {
    category: analysis.category,
    totalFindings: findings.length,
    findings: findings.map((finding) => ({
      tier: finding.tier,
      category: finding.category,
      match: String(finding.match || '').slice(0, 240),
      index: finding.index,
      reason: finding.reason,
      target: finding.target || null,
      impact: finding.impact || impactFor(finding.category),
      snippet: String(finding.match || '').replace(/^[\r\n]+/, '').slice(0, 160),
    })),
    autoApproved: autoApproved.map((entry) => ({
      match: String(entry.raw || '').slice(0, 240),
      index: entry.index,
      reason: entry.reason,
    })),
  };
}
