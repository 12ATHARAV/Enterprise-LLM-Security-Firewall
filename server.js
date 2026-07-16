const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC = path.join(__dirname, 'public');
const auditLog = [];
const counters = { requests: 0, blocked: 0, redacted: 0, allowed: 0, tokens: 0 };

const policies = [
  { id: 'POL-001', name: 'Production secret isolation', appliesTo: 'Developer', rule: 'Block requests for production credentials, keys, or secrets.', status: 'Enforced' },
  { id: 'POL-002', name: 'Legal document boundary', appliesTo: 'Finance', rule: 'Deny access to legal and privileged records.', status: 'Enforced' },
  { id: 'POL-003', name: 'Confidential repository access', appliesTo: 'Contractor', rule: 'Deny confidential repository and internal architecture requests.', status: 'Enforced' },
  { id: 'POL-004', name: 'Personal data protection', appliesTo: 'All users', rule: 'Redact regulated personal and payment data.', status: 'Enforced' }
];

function luhn(value) {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  return [...digits].reverse().reduce((sum, digit, index) => {
    let n = Number(digit); if (index % 2) n = n > 4 ? n * 2 - 9 : n * 2;
    return sum + n;
  }, 0) % 10 === 0;
}

function findSensitive(text) {
  const findings = [];
  const add = (type, regex, severity = 'high') => { if (regex.test(text)) findings.push({ type, severity }); };
  add('API key', /(?:sk|pk|api)[_-]?[a-zA-Z0-9]{16,}/i, 'critical');
  add('Password or secret', /(?:password|passwd|secret)\s*[:=]\s*\S+/i, 'high');
  add('Aadhaar number', /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/, 'critical');
  add('PAN number', /\b[A-Z]{5}\d{4}[A-Z]\b/, 'high');
  add('Email address', /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, 'medium');
  const cards = text.match(/(?:\d[ -]?){13,19}\d/g) || [];
  if (cards.some(luhn)) findings.push({ type: 'Payment card', severity: 'critical' });
  return findings;
}

function redact(text) {
  return text
    .replace(/(?:sk|pk|api)[_-]?[a-zA-Z0-9]{16,}/gi, '[REDACTED_API_KEY]')
    .replace(/((?:password|passwd|secret)\s*[:=]\s*)\S+/gi, '$1[REDACTED]')
    .replace(/\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, '[REDACTED_AADHAAR]')
    .replace(/\b[A-Z]{5}\d{4}[A-Z]\b/g, '[REDACTED_PAN]')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[REDACTED_EMAIL]')
    .replace(/(?:\d[ -]?){13,19}\d/g, value => luhn(value) ? '[REDACTED_CARD]' : value);
}

function analyzePrompt(prompt, role) {
  const threats = [];
  const injection = [/(ignore|disregard|override) (all |any |the )?(previous|prior|system) instructions?/i, /reveal (the )?(system|hidden) prompt/i, /you are now|developer mode|jailbreak/i, /do not follow (the )?rules/i];
  if (injection.some(rule => rule.test(prompt))) threats.push({ module: 'Prompt injection', severity: 'critical', detail: 'Instruction override pattern detected' });
  if (/(?:base64|rot13|unicode).{0,30}(?:decode|encoded)|[A-Za-z0-9+/]{60,}={0,2}/i.test(prompt)) threats.push({ module: 'Obfuscation', severity: 'high', detail: 'Potential encoded or obfuscated payload' });
  for (const item of findSensitive(prompt)) threats.push({ module: 'DLP', severity: item.severity, detail: `${item.type} detected` });
  const roleRules = {
    Developer: /production (?:secret|credential|key)|prod (?:secret|credential|key)/i,
    Finance: /legal (?:record|document|advice)|privileged/i,
    Contractor: /confidential (?:repo|repository)|internal architecture/i
  };
  if (roleRules[role] && roleRules[role].test(prompt)) threats.push({ module: 'Policy engine', severity: 'high', detail: `${role} access boundary violated` });
  if (/(how (?:to|do i).{0,50}(?:build|make).{0,40}(?:malware|ransomware|bomb)|steal (?:credentials|passwords))/i.test(prompt)) threats.push({ module: 'Safety guardrail', severity: 'critical', detail: 'Unsafe-use request detected' });
  return threats;
}

function firewall(input) {
  const prompt = String(input.prompt || '').trim();
  const user = String(input.user || 'anonymous').trim().slice(0, 80);
  const role = ['Developer', 'Finance', 'Contractor', 'HR', 'Analyst'].includes(input.role) ? input.role : 'Analyst';
  if (!prompt) return { error: 'A prompt is required.' };
  const threats = analyzePrompt(prompt, role);
  const block = threats.some(t => ['critical', 'high'].includes(t.severity) && t.module !== 'DLP');
  const sanitizedPrompt = redact(prompt.replace(/ignore previous instructions/gi, '[removed instruction override]'));
  let response = block ? 'Request blocked by Sentinel policy. No request was sent to the language model.' : `Secure model response: I can help with a safe, policy-compliant answer to: “${sanitizedPrompt}”`;
  const outputFindings = findSensitive(response);
  if (outputFindings.length) response = redact(response);
  const inputTokens = Math.max(1, Math.ceil(prompt.length / 4));
  const outputTokens = block ? 0 : Math.ceil(response.length / 4);
  const decision = block ? 'BLOCKED' : threats.length || outputFindings.length ? 'SANITIZED' : 'ALLOWED';
  const event = { id: crypto.randomUUID().slice(0, 8).toUpperCase(), timestamp: new Date().toISOString(), user, role, prompt: sanitizedPrompt, decision, threats, inputTokens, outputTokens, model: input.model || 'enterprise-gpt-4.1', response };
  auditLog.unshift(event); if (auditLog.length > 100) auditLog.pop();
  counters.requests++; counters.tokens += inputTokens + outputTokens;
  if (decision === 'BLOCKED') counters.blocked++; else if (decision === 'SANITIZED') counters.redacted++; else counters.allowed++;
  return event;
}

function send(res, status, data, type = 'application/json') { res.writeHead(status, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-store' }); res.end(type === 'application/json' ? JSON.stringify(data) : data); }
function serveFile(res, file) { const safe = path.normalize(file).replace(/^([.][.][\\/])+/, ''); const target = path.join(PUBLIC, safe || 'index.html'); if (!target.startsWith(PUBLIC) || !fs.existsSync(target)) return send(res, 404, { error: 'Not found' }); const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.svg': 'image/svg+xml' }; send(res, 200, fs.readFileSync(target), types[path.extname(target)] || 'application/octet-stream'); }

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === 'GET' && url.pathname === '/api/metrics') return send(res, 200, { ...counters, totalEvents: auditLog.length, protectionRate: counters.requests ? Math.round(((counters.blocked + counters.redacted) / counters.requests) * 100) : 0 });
  if (req.method === 'GET' && url.pathname === '/api/audit') return send(res, 200, auditLog);
  if (req.method === 'GET' && url.pathname === '/api/policies') return send(res, 200, policies);
  if (req.method === 'POST' && url.pathname === '/api/inspect') { let body = ''; req.on('data', c => { body += c; if (body.length > 100000) req.destroy(); }); req.on('end', () => { try { const result = firewall(JSON.parse(body)); send(res, result.error ? 400 : 200, result); } catch { send(res, 400, { error: 'Invalid JSON payload.' }); } }); return; }
  if (req.method === 'GET') return serveFile(res, url.pathname === '/' ? 'index.html' : url.pathname);
  send(res, 405, { error: 'Method not allowed' });
});
if (require.main === module) server.listen(PORT, () => console.log(`Sentinel firewall listening on http://localhost:${PORT}`));
module.exports = { firewall, analyzePrompt, findSensitive, redact, luhn, server };
