import { spawnSync } from 'node:child_process';

const HIGH_RISK = [
  { id: 'private-key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'aws-access-key', re: /(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}/g },
  { id: 'github-token', re: /gh[pousr]_[A-Za-z0-9]{20,}/g },
  { id: 'slack-token', re: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { id: 'stripe-key', re: /sk_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { id: 'google-api-key', re: /AIza[0-9A-Za-z_\-]{30,}/g },
  { id: 'openai-anthropic-key', re: /sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{24,}/g },
  { id: 'supabase-or-jwt-secret', re: /sb_(?:secret|preselect)_[A-Za-z0-9_\-]{16,}|sbp_[a-f0-9]{32,}|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}/g },
  { id: 'cloudflare-api-token', re: /v1\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}/g },
  { id: 'brevo-key', re: /xkeysib-[a-f0-9]{20,40}\-[A-Za-z0-9]{12,}/g },
  { id: 'url-with-credentials', re: /[a-z][a-z0-9+.-]*:\/\/[^/\s:@'"]{2,}:[^/\s@'"&]{6,}@[a-z0-9.\-_]{3,}/gi },
  // Forma de credencial: 16+ caracteres com maiuscula, minuscula e digito.
  // Slugs de fixture como "change-password" e "Portfolio123" ficam fora por construcao.
  { id: 'credential-assignment-shape', re: /(secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd)\s*[:=]\s*['"](?=[^'"\s]{16,})(?=[^'"\s]*[a-z])(?=[^'"\s]*[A-Z])(?=[^'"\s]*[0-9])[^'"\s]{16,}['"]/gi },
];

const ENTROPY_EXCLUDE = /(node_modules|package-lock|go\.sum|\.lock$|\.lock\/|composer\.lock|Cargo\.lock|poetry\.lock|Pipfile\.lock|\.min\.|\.map$|\.pdf$|\.docx$|\.svg$|\.snap$|__snapshots__|dist\/|build\/)/;
// Arquivos que contem as proprias assinaturas de deteccao nao sao credenciais.
const SIGNATURE_FILES = /(\.gitleaks\.toml|tools\/secret-scan\.mjs|hooks\/pre-push)$/;
const ENTROPY_ALLOW = /(Segura123|Errada123|SenhaNova2|SenhaAntiga1|SenhaErrada1|OutraSenha3|OutraNova3|Excluir123|Password123|Portfolio123|CANARY|EXAMPLE|brevo_test_only|ExponentPushToken|unsplash|example\.(com|test))/;
const MIN_TOKEN_LEN = 24;
const ENTROPY_THRESHOLD = 4.3;

function shannon(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function git(args) {
  const r = spawnSync('git', args, { cwd: repoDir, encoding: 'buffer', maxBuffer: 1 << 30 });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr.toString('utf8')}`);
  return r.stdout;
}

const repoDir = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : '.';
const fullHistory = !process.argv.includes('--worktree-only');
const rangeIdx = process.argv.indexOf('--range');
const range = rangeIdx > 0 ? process.argv[rangeIdx + 1] : null;

const objects = [];
if (range) {
  const text = git(['rev-list', '--objects', range]).toString('utf8');
  for (const line of text.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp > 0) objects.push({ sha: line.slice(0, sp), path: line.slice(sp + 1) });
  }
  console.log(`Modo intervalo: ${range}`);
} else if (fullHistory) {
  const text = git(['rev-list', '--objects', '--all']).toString('utf8');
  for (const line of text.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp > 0) objects.push({ sha: line.slice(0, sp), path: line.slice(sp + 1) });
  }
} else {
  const text = git(['ls-files', '-z']).toString('utf8');
  for (const path of text.split('\0').filter(Boolean)) {
    const sha = git(['hash-object', path]).toString('utf8').trim();
    objects.push({ sha, path });
  }
}

if (!objects.length) {
  if (range) {
    console.log('Nenhum objeto novo no intervalo — nada a varrer.');
    process.exit(0);
  }
  console.error('Nenhum objeto para varrer.');
  process.exit(2);
}

const pathOf = new Map(objects.map((o) => [o.sha, o.path]));
const batch = spawnSync('git', ['cat-file', '--batch'], {
  cwd: repoDir, input: objects.map((o) => o.sha).join('\n'), maxBuffer: 1 << 30,
});
if (batch.status !== 0) {
  console.error(batch.stderr.toString('utf8'));
  process.exit(2);
}

const findings = [];
const buf = batch.stdout;
let pos = 0;
let scanned = 0;

while (pos < buf.length) {
  const nl = buf.indexOf(0x0a, pos);
  if (nl < 0) break;
  const header = buf.subarray(pos, nl).toString('utf8').split(' ');
  if (header.length < 3 || header[1] !== 'blob') { pos = nl + 1; continue; }
  const [, , sizeStr] = header;
  const size = Number(sizeStr);
  const raw = buf.subarray(nl + 1, nl + 1 + size);
  pos = nl + 1 + size + 1;
  const path = pathOf.get(header[0]) ?? '(desconhecido)';
  if (SIGNATURE_FILES.test(path)) continue;
  if (ENTROPY_EXCLUDE.test(path) || raw.includes(0) || size > 3_000_000) continue;
  scanned++;
  const content = raw.toString('utf8');

  for (const rule of HIGH_RISK) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(content)) !== null) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      if (ENTROPY_ALLOW.test(m[0])) continue;
      const line = content.slice(0, m.index).split('\n').length;
      findings.push({ kind: rule.id, path, line, severity: 'HIGH', token: mask(m[0]) });
    }
  }

  if (ENTROPY_EXCLUDE.test(path)) continue;
  for (const m of content.matchAll(/[A-Za-z0-9+_\-]{24,}/g)) {
    const tok = m[0];
    if (tok.length > 400 || ENTROPY_ALLOW.test(tok)) continue;
    if (/^[a-f0-9]{40,}$/.test(tok)) continue;
    if (!/[A-Z]/.test(tok) || !/[a-z]/.test(tok) || !/[0-9]/.test(tok)) continue;
    if (isSequentialCharset(tok)) continue;
    const lineStart = content.lastIndexOf('\n', m.index) + 1;
    const before = content.slice(lineStart, m.index);
    if (/https?:\/\/[^\s'"<>]*$/.test(before)) continue;
    if (shannon(tok) < ENTROPY_THRESHOLD) continue;
    const line = content.slice(0, m.index).split('\n').length;
    findings.push({ kind: 'high-entropy-token', path, line, severity: 'REVIEW', token: mask(tok) });
  }
}

function isSequentialCharset(s) {
  let up = 0;
  let down = 0;
  for (let i = 1; i < s.length; i++) {
    const d = s.charCodeAt(i) - s.charCodeAt(i - 1);
    if (d === 1) up++;
    else if (d === -1) down++;
  }
  return up + down > s.length * 0.7;
}

function mask(t) {
  const keep = Math.max(3, Math.floor(t.length * 0.15));
  return `${t.slice(0, keep)}…${t.slice(-2)}`;
}

const seen = new Set();
const unique = findings.filter((f) => {
  const k = `${f.kind}|${f.path}|${f.token}`;
  if (seen.has(k)) return false;
  seen.add(k);
  return true;
});

console.log(`Objetos varridos: ${scanned} · histórico completo: ${fullHistory}`);
for (const f of unique) {
  console.log(`  [${f.severity}] ${f.kind} :: ${f.path}:${f.line} ${f.token}`);
}

const high = unique.filter((f) => f.severity === 'HIGH').length;
const review = unique.length - high;
console.log(`\nResultado: ${high} credencial(is) de alto risco, ${review} candidato(s) para revisão.`);

if (high > 0) {
  console.error('\nBloqueado: credencial de alto risco no código. Remova do histórico e rotacione no provedor.');
  process.exit(1);
}
if (review > 0 && process.argv.includes('--strict-entropy')) {
  console.error('\nBloqueado em modo estrito: token de alta entropia não classificado.');
  process.exit(1);
}
