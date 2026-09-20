/**
 * MCP configuration scanner (`traceshield scan`, v0.5.0).
 *
 * Scans common MCP client config files — Claude Desktop
 * (`claude_desktop_config.json`), project-scope `.mcp.json`, `.cursor/mcp.json`,
 * `.vscode/mcp.json` and friends — for tool-description poisoning patterns:
 *
 *   - instruction-override phrases smuggled into tool descriptions,
 *   - hidden Unicode characters (zero-width marks, bidi controls) used to
 *     hide instructions from visual review,
 *   - dangerous permission combos (permissive execution flags, shell wrappers
 *     combined with secrets in the environment, wildcard tool allowlists,
 *     root filesystem mounts).
 *
 * Detection only — findings are advisory. Wire `traceshield scan --json` into
 * CI: the command exits `1` when any high/critical finding is present.
 */

import * as fs from 'node:fs';

export type ScanSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface ScanFinding {
  ruleId: string;
  severity: ScanSeverity;
  title: string;
  detail: string;
  file: string;
  /** MCP server name the finding belongs to, when attributable. */
  server?: string;
  /** Dotted path of the field the finding was found in. */
  field?: string;
  /** Matched text, with control characters escaped so hidden chars are visible. */
  evidence?: string;
}

export interface ScanResult {
  file: string;
  /** Detected config flavor: claude-desktop | vscode | cursor | generic-mcp | invalid. */
  format: string;
  servers: number;
  findings: ScanFinding[];
}

export interface ScanReport {
  scannedAt: string;
  files: number;
  servers: number;
  findings: ScanFinding[];
}

// ── Rule catalogs ─────────────────────────────────────────────────────────

/** Instruction-override / poisoning phrases looked for in text fields. */
export const OVERRIDE_PATTERNS: Array<{ regex: RegExp; label: string }> = [
  { regex: /ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directions?)/i, label: 'instruction override' },
  { regex: /disregard\s+(all|any)\s+(previous|prior|above)\s+(instructions?|prompts?|rules?)/i, label: 'instruction override' },
  { regex: /forget\s+(everything|all|your|what)\s+(you\s+)?(were\s+)?(told|instructed|learned|know)/i, label: 'memory reset' },
  { regex: /you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|uncensored|jailbroken)/i, label: 'role redefinition' },
  { regex: /reveal\s+(your\s+)?(system\s+prompt|instructions?|hidden\s+prompt)/i, label: 'system prompt extraction' },
  { regex: /do\s+not\s+(tell|inform|notify|mention)\s+(the\s+)?user/i, label: 'user concealment' },
  { regex: /(hide|conceal)\s+(this|these)\s+(instructions?|tools?|capabilities?)/i, label: 'capability concealment' },
  { regex: /exfiltrat(e|es|ed|ion)/i, label: 'exfiltration language' },
  { regex: /(send|upload|post)\s+(all\s+|the\s+)?(conversation|chat|history|data|credentials?|api\s?keys?|tokens?)\s+(to|via)/i, label: 'data exfiltration' },
];

/** Hidden / confusable Unicode ranges with per-range severity. */
export const HIDDEN_UNICODE_RANGES: Array<{ start: number; end: number; label: string; severity: ScanSeverity }> = [
  { start: 0x200B, end: 0x200F, label: 'zero-width and direction marks (U+200B–U+200F)', severity: 'high' },
  { start: 0x202A, end: 0x202E, label: 'bidi embedding overrides (U+202A–U+202E)', severity: 'high' },
  { start: 0x2060, end: 0x2064, label: 'invisible operators / word joiners (U+2060–U+2064)', severity: 'high' },
  { start: 0x2066, end: 0x2069, label: 'bidi isolates (U+2066–U+2069)', severity: 'high' },
  { start: 0xFE00, end: 0xFE0F, label: 'variation selectors (U+FE00–U+FE0F)', severity: 'low' },
  { start: 0xFEFF, end: 0xFEFF, label: 'zero-width no-break space (U+FEFF)', severity: 'low' },
  { start: 0xFFF9, end: 0xFFFB, label: 'interlinear annotation anchors (U+FFF9–U+FFFB)', severity: 'medium' },
];

const SHELL_COMMANDS = new Set(['bash', 'sh', 'zsh', 'fish', 'powershell', 'pwsh', 'cmd', 'cmd.exe']);
const NETWORK_TOOLS = /\b(curl|wget|nc|ncat|netcat|socat)\b/i;
const SECRET_ENV_KEY = /(?:API[-_]?KEYS?|TOKENS?|SECRETS?|PASSWORDS?|PASSPHRASES?|CREDENTIALS?)/i;
const PERMISSIVE_FLAGS = /--dangerously-skip-permissions|--yolo/i;
const WILDCARD_ALLOWLIST = /^\*$/;
const ALLOWLIST_FIELDS = ['allowedTools', 'allowed_tools', 'permissions', 'allow'];

const severityRank: Record<ScanSeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// ── Helpers ───────────────────────────────────────────────────────────────

/** Escape control and hidden characters so they are visible in reports. */
export function visibleText(input: string): string {
  let out = '';
  for (const ch of input) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f || isHiddenUnicode(ch)) {
      out += `\\u${code.toString(16).padStart(4, '0')}`;
    } else {
      out += ch;
    }
  }
  return out;
}

/** True when the character belongs to one of the hidden-Unicode ranges. */
export function isHiddenUnicode(ch: string): boolean {
  const code = ch.codePointAt(0) ?? 0;
  return HIDDEN_UNICODE_RANGES.some((r) => code >= r.start && code <= r.end);
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

/** Detects hidden-Unicode characters in a string, grouped by range. */
export function detectHiddenUnicode(text: string): Array<{ label: string; severity: ScanSeverity; chars: string[] }> {
  const hits = new Map<string, { label: string; severity: ScanSeverity; chars: string[] }>();
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    for (const range of HIDDEN_UNICODE_RANGES) {
      if (code >= range.start && code <= range.end) {
        const entry = hits.get(range.label) ?? { label: range.label, severity: range.severity, chars: [] };
        if (!entry.chars.includes(ch)) entry.chars.push(ch);
        hits.set(range.label, entry);
        break;
      }
    }
  }
  return [...hits.values()];
}

// ── Server extraction ─────────────────────────────────────────────────────

const SERVER_MAP_KEYS = /^mcp[-_]?servers$|^servers$/i;

export interface ServerEntry {
  name: string;
  /** Dotted path prefix, e.g. `mcpServers.web-search`. */
  path: string;
  command?: string;
  args: string[];
  env: Record<string, string>;
  /** Raw config entry, for fields the normalizer does not interpret. */
  raw: Record<string, unknown>;
}

/**
 * Extract MCP server entries from a parsed config object.
 * Supports `{ "mcpServers": { name: {...} } }` (Claude Desktop / `.mcp.json` /
 * Cursor), `{ "servers": { name: {...} } }` (VS Code), and config files whose
 * root object is the server map itself.
 */
export function extractServers(config: unknown): ServerEntry[] {
  const out: ServerEntry[] = [];
  if (!config || typeof config !== 'object' || Array.isArray(config)) return out;

  const root = config as Record<string, unknown>;
  for (const [key, value] of Object.entries(root)) {
    if (!SERVER_MAP_KEYS.test(key)) continue;
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
    for (const [name, entry] of Object.entries(value as Record<string, unknown>)) {
      const parsed = toServerEntry(entry);
      if (parsed) out.push({ name, path: `${key}.${name}`, ...parsed });
    }
  }

  if (out.length === 0) {
    // Root-level server map: { "my-server": { command: ... }, ... }
    for (const [name, entry] of Object.entries(root)) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      const e = entry as Record<string, unknown>;
      if (!('command' in e || 'url' in e || 'type' in e)) continue;
      const parsed = toServerEntry(entry);
      if (parsed) out.push({ name, path: name, ...parsed });
    }
  }
  return out;
}

function toServerEntry(entry: unknown): Omit<ServerEntry, 'name' | 'path'> | null {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
  const e = entry as Record<string, unknown>;
  const command = typeof e['command'] === 'string' ? e['command'] : undefined;
  const url = typeof e['url'] === 'string' ? e['url'] : undefined;
  if (command === undefined && url === undefined) return null;
  const args = Array.isArray(e['args']) ? e['args'].filter((a): a is string => typeof a === 'string') : [];
  const env: Record<string, string> = {};
  if (e['env'] && typeof e['env'] === 'object' && !Array.isArray(e['env'])) {
    for (const [k, v] of Object.entries(e['env'] as Record<string, unknown>)) {
      if (typeof v === 'string') env[k] = v;
    }
  }
  return { command, args, env, raw: e };
}

// ── Config scanning ───────────────────────────────────────────────────────

function detectFormat(filePath: string): string {
  const normalized = filePath.replace(/\\/g, '/');
  const base = normalized.split('/').pop() ?? normalized;
  if (/^claude_desktop_config\.json$/i.test(base)) return 'claude-desktop';
  if (/\.cursor\//i.test(normalized)) return 'cursor';
  if (/\.vscode\//i.test(normalized)) return 'vscode';
  return 'generic-mcp';
}

/** Scan a parsed MCP config object. `filePath` is used for attribution only. */
export function scanObject(config: unknown, filePath: string): ScanResult {
  const findings: ScanFinding[] = [];
  const servers = extractServers(config);
  const format = detectFormat(filePath);

  // 1. Server-level permission heuristics.
  for (const entry of servers) {
    findings.push(...scanServer(entry, filePath));
  }

  // 2. Text-field scan across every string leaf (descriptions, args, env...).
  walkStrings(config, (value, path) => {
    findings.push(...scanText(value, filePath, path, servers));
  });

  return { file: filePath, format, servers: servers.length, findings };
}

function scanServer(entry: ServerEntry, filePath: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const joined = [entry.command ?? '', ...entry.args].join(' ');

  const shell = entry.command !== undefined
    && (SHELL_COMMANDS.has(entry.command.toLowerCase()) || /\/bin\/(ba)?sh$/.test(entry.command));
  const networked = NETWORK_TOOLS.test(joined);

  const permissive = entry.args.find((a) => PERMISSIVE_FLAGS.test(a));
  if (permissive) {
    findings.push({
      ruleId: 'MCP003',
      severity: 'critical',
      title: 'permissive execution flag',
      detail: 'The server launches with a flag that disables permission checks (--dangerously-skip-permissions / --yolo). Any tool it hosts can act without confirmation.',
      file: filePath,
      server: entry.name,
      field: `${entry.path}.args`,
      evidence: permissive,
    });
  }

  if (shell) {
    findings.push({
      ruleId: 'MCP004',
      severity: 'high',
      title: 'shell wrapper command',
      detail: 'The server command is a shell, giving hosted tools an arbitrary command-execution surface. Prefer a dedicated, least-privilege server binary.',
      file: filePath,
      server: entry.name,
      field: `${entry.path}.command`,
      evidence: entry.command,
    });
  }

  const secretKeys = Object.keys(entry.env).filter((k) => SECRET_ENV_KEY.test(k));
  if (secretKeys.length > 0 && (networked || shell)) {
    findings.push({
      ruleId: 'MCP005',
      severity: 'high',
      title: 'secrets exposed to a network-capable server',
      detail: `Environment variables ${secretKeys.join(', ')} look like secrets and the server has a shell/network capability — one tool-description poisoning away from credential exfiltration.`,
      file: filePath,
      server: entry.name,
      field: `${entry.path}.env`,
      evidence: secretKeys.join(', '),
    });
  }

  for (const key of ALLOWLIST_FIELDS) {
    const value = entry.raw[key];
    if (typeof value === 'string' && WILDCARD_ALLOWLIST.test(value)) {
      findings.push({
        ruleId: 'MCP006',
        severity: 'medium',
        title: 'wildcard tool allowlist',
        detail: `The "${key}" entry is "*" — every tool the server exposes is auto-approved with no allowlist.`,
        file: filePath,
        server: entry.name,
        field: `${entry.path}.${key}`,
        evidence: '*',
      });
    }
  }

  for (let i = 0; i < entry.args.length; i++) {
    const arg = entry.args[i] ?? '';
    if (!/^(--volume|-v)$/.test(arg)) continue;
    const target = entry.args[i + 1] ?? '';
    const source = (target.split(':')[0] ?? '').trim();
    if (/^(\/|~\/?|\/home|\/Users|\/root|[A-Za-z]:\\?)$/.test(source)) {
      findings.push({
        ruleId: 'MCP007',
        severity: 'high',
        title: 'root-level filesystem mount',
        detail: `The volume mount "${target}" exposes a filesystem root (or the whole home directory) to the container — file tools can read or overwrite everything under it.`,
        file: filePath,
        server: entry.name,
        field: `${entry.path}.args`,
        evidence: target,
      });
    }
  }

  return findings;
}

function walkStrings(node: unknown, visit: (value: string, path: string) => void, path = ''): void {
  if (typeof node === 'string') {
    visit(node, path || '<root>');
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((item, i) => walkStrings(item, visit, `${path}[${i}]`));
    return;
  }
  if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      const childPath = path ? `${path}.${key}` : key;
      if (typeof value === 'string') visit(value, childPath);
      else walkStrings(value, visit, childPath);
    }
  }
}

function scanText(text: string, filePath: string, field: string, servers: ServerEntry[]): ScanFinding[] {
  if (text.length === 0) return [];
  const findings: ScanFinding[] = [];
  const server = servers.find((s) => field.startsWith(`${s.path}.`));

  for (const pattern of OVERRIDE_PATTERNS) {
    const match = pattern.regex.exec(text);
    if (match) {
      findings.push({
        ruleId: 'MCP001',
        severity: 'high',
        title: `instruction-override phrase (${pattern.label})`,
        detail: `A text field contains a phrase used to hijack agent behavior ("${pattern.label}"). Tool descriptions and config strings are attacker-visible prompt surface.`,
        file: filePath,
        server: server?.name,
        field,
        evidence: truncate(visibleText(match[0] ?? ''), 120),
      });
      break; // one override finding per field is enough signal
    }
  }

  for (const hit of detectHiddenUnicode(text)) {
    findings.push({
      ruleId: 'MCP002',
      severity: hit.severity,
      title: `hidden Unicode characters (${hit.label})`,
      detail: `Field contains invisible characters (${hit.chars.map((c) => `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`).join(', ')}) commonly used to smuggle instructions past visual review.`,
      file: filePath,
      server: server?.name,
      field,
      evidence: truncate(visibleText(text), 120),
    });
  }

  return findings;
}

/** Scan raw file content (JSON, or YAML for .yaml/.yml files). */
export async function scanConfigText(filePath: string, content: string): Promise<ScanResult> {
  const isYaml = /\.ya?ml$/i.test(filePath);
  let data: unknown;
  try {
    if (isYaml) {
      const { parse } = await import('yaml');
      data = parse(content);
    } else {
      data = JSON.parse(content);
    }
  } catch (err) {
    return {
      file: filePath,
      format: 'invalid',
      servers: 0,
      findings: [{
        ruleId: 'MCP000',
        severity: 'medium',
        title: isYaml ? 'invalid YAML' : 'invalid JSON',
        detail: `Config file could not be parsed: ${err instanceof Error ? err.message : String(err)}`,
        file: filePath,
      }],
    };
  }
  return scanObject(data, filePath);
}

// ── File discovery ────────────────────────────────────────────────────────

const KNOWN_CONFIG_NAMES = [
  'claude_desktop_config.json',
  '.mcp.json',
  'mcp.json',
  '.cursor/mcp.json',
  '.vscode/mcp.json',
  '.codeium/windsurf/mcp_config.json',
];

/** Well-known per-platform config locations (Claude Desktop etc.). */
export function defaultSearchPaths(
  home: string,
  platform: string,
  env: Record<string, string | undefined>,
): string[] {
  const paths: string[] = ['.mcp.json', 'mcp.json', '.cursor/mcp.json', '.vscode/mcp.json'];
  if (platform === 'win32') {
    const appData = env['APPDATA'];
    if (appData) paths.push(`${appData}\\Claude\\claude_desktop_config.json`);
  } else if (platform === 'darwin') {
    paths.push(`${home}/Library/Application Support/Claude/claude_desktop_config.json`);
  } else {
    paths.push(`${home}/.config/Claude/claude_desktop_config.json`);
  }
  return paths;
}

/**
 * Expand user-supplied paths: files are taken as-is, directories are searched
 * for the known config file names. When `inputs` is empty, the well-known
 * per-platform locations are used instead. Only existing files are returned.
 */
export function collectConfigPaths(
  inputs: string[],
  existsSync: (p: string) => boolean,
  statIsDirectory: (p: string) => boolean,
  defaultInputs: string[] = defaultSearchPaths(
    process.env['HOME'] ?? process.env['USERPROFILE'] ?? '',
    process.platform,
    process.env,
  ),
): string[] {
  const seeds = inputs.length > 0 ? inputs : defaultInputs;
  const out: string[] = [];
  for (const input of seeds) {
    if (!existsSync(input)) continue;
    if (!statIsDirectory(input)) {
      out.push(input);
      continue;
    }
    for (const name of KNOWN_CONFIG_NAMES) {
      const candidate = `${input.replace(/[\\/]+$/, '')}/${name}`;
      if (existsSync(candidate)) out.push(candidate);
    }
  }
  return [...new Set(out)];
}

// ── Report assembly & rendering ───────────────────────────────────────────

export function buildReport(results: ScanResult[], scannedAt = new Date().toISOString()): ScanReport {
  const findings = results
    .flatMap((r) => r.findings)
    .sort((a, b) =>
      severityRank[b.severity] - severityRank[a.severity]
      || a.file.localeCompare(b.file)
      || a.ruleId.localeCompare(b.ruleId));
  return {
    scannedAt,
    files: results.length,
    servers: results.reduce((sum, r) => sum + r.servers, 0),
    findings,
  };
}

/** Scan the given files/directories and assemble a report. */
export async function scanPaths(
  paths: string[],
  existsSync: (p: string) => boolean = (p) => fs.existsSync(p),
  readFileSync: (p: string) => string = (p) => fs.readFileSync(p, 'utf-8'),
): Promise<ScanReport> {
  const files = collectConfigPaths(paths, existsSync, (p) => {
    try {
      return fs.statSync(p).isDirectory();
    } catch {
      return false;
    }
  });
  const results: ScanResult[] = [];
  for (const file of files) {
    let content = '';
    try {
      content = readFileSync(file);
    } catch (err) {
      results.push({
        file,
        format: 'invalid',
        servers: 0,
        findings: [{
          ruleId: 'MCP000',
          severity: 'medium',
          title: 'unreadable file',
          detail: `Config file could not be read: ${err instanceof Error ? err.message : String(err)}`,
          file,
        }],
      });
      continue;
    }
    results.push(await scanConfigText(file, content));
  }
  return buildReport(results, new Date().toISOString());
}

export function renderReport(report: ScanReport, opts: { json?: boolean } = {}): string {
  if (opts.json) return `${JSON.stringify(report, null, 2)}\n`;

  const counts: Record<string, number> = {};
  for (const f of report.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const countSummary = Object.entries(counts).map(([sev, n]) => `${n} ${sev}`).join(', ') || 'none';

  const lines: string[] = [];
  lines.push(`traceshield scan — ${report.files} file(s), ${report.servers} server(s), ${report.findings.length} finding(s) [${countSummary}]`);
  if (report.findings.length === 0) {
    lines.push('');
    lines.push('No poisoning patterns or dangerous permission combos found.');
    return `${lines.join('\n')}\n`;
  }
  for (const f of report.findings) {
    lines.push('');
    lines.push(`  [${f.severity.toUpperCase()}] ${f.ruleId} ${f.title}`);
    lines.push(`    file: ${f.file}${f.server ? ` · server: ${f.server}` : ''}${f.field ? ` · field: ${f.field}` : ''}`);
    lines.push(`    ${f.detail}`);
    if (f.evidence) lines.push(`    evidence: "${f.evidence}"`);
  }
  lines.push('');
  lines.push('Exit code 1 indicates high/critical findings. Review affected servers, pin trusted configs, re-run `traceshield scan` until clean.');
  return `${lines.join('\n')}\n`;
}
