import { createHash } from 'node:crypto';
import { appendFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const APP_NAME = 'hello-world';
const GITHUB_API = 'https://api.github.com';

function required(env, name) {
  if (!env[name]?.trim()) throw new Error(`Missing required environment variable: ${name}`);
  return env[name];
}

function serviceEndpoint(env, name, path) {
  const value = required(env, name).trim();
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Invalid ${name}; expected an HTTPS base URL from your service key.`);
  }
  if (url.protocol !== 'https:' || url.username || url.password || value.includes('?') || value.includes('#')) {
    throw new Error(`Invalid ${name}; use HTTPS without embedded credentials, query strings, or fragments.`);
  }
  url.pathname = url.pathname.replace(/\/+$/, '') + path;
  return url.href;
}

export function serviceEndpoints(env) {
  return {
    tokenUrl: serviceEndpoint(env, 'AVR_UAA_URL', '/oauth/token'),
    findingsUrl: serviceEndpoint(env, 'AVR_BASE_URL', '/api/v1/provider/Findings'),
  };
}

// Do not include response bodies, URLs with query strings, or credentials in errors.
export async function requestJson(url, options, fetchImpl = fetch, service = 'API') {
  let response;
  try {
    response = await fetchImpl(url, {
      ...options,
      redirect: 'error',
      signal: AbortSignal.timeout(60_000),
    });
  } catch {
    throw new Error(`${service} request failed (network error, timeout, or rejected redirect).`);
  }
  if (!response.ok) throw new Error(`${service} request failed: HTTP ${response.status}.`);
  try {
    return await response.json();
  } catch {
    throw new Error(`${service} returned invalid JSON.`);
  }
}

export async function getAccessToken(env, fetchImpl = fetch) {
  const tokenUrl = serviceEndpoint(env, 'AVR_UAA_URL', '/oauth/token');
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: required(env, 'AVR_CLIENT_ID'),
    client_secret: required(env, 'AVR_CLIENT_SECRET'),
  });
  if (env.AVR_SCOPE?.trim()) body.set('scope', env.AVR_SCOPE.trim());
  const result = await requestJson(tokenUrl, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  }, fetchImpl, 'OAuth');
  if (typeof result?.access_token !== 'string' || !result.access_token.trim() || /\s/.test(result.access_token)) {
    throw new Error('OAuth response is missing a valid access_token.');
  }
  return result.access_token;
}

export function filterFindings(value) {
  if (!Array.isArray(value) || value.some(item => !item || typeof item !== 'object' || Array.isArray(item))) {
    throw new Error('AVR response must contain a value array of finding objects.');
  }
  return value.filter(item => item.appName === APP_NAME);
}

export async function retrieveFindings(token, fetchImpl = fetch, env = process.env) {
  // Local filtering is mandatory. Enable the optional server-side filter only
  // after confirming that this beta endpoint supports OData $filter.
  const first = new URL(serviceEndpoint(env, 'AVR_BASE_URL', '/api/v1/provider/Findings'));
  if (env.AVR_SERVER_FILTER === 'true') {
    first.searchParams.set('$filter', `appName eq '${APP_NAME}'`);
  }
  let url = first;
  const visited = new Set();
  const findings = new Map();
  while (url) {
    if (url.origin !== first.origin || url.username || url.password || url.hash) {
      throw new Error('Rejected unsafe AVR pagination link.');
    }
    if (visited.has(url.href) || visited.size >= 1000) throw new Error('AVR pagination loop or page limit exceeded.');
    visited.add(url.href);
    const page = await requestJson(url.href, {
      method: 'GET',
      headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
    }, fetchImpl, 'AVR');
    for (const finding of filterFindings(page?.value)) {
      if (typeof finding.id !== 'string' || !finding.id.trim()) throw new Error('Matching AVR finding is missing its stable id.');
      findings.set(finding.id, finding);
    }
    const next = page['@odata.nextLink'];
    if (next != null && (typeof next !== 'string' || !next.trim())) throw new Error('Invalid AVR pagination link.');
    try {
      url = next == null ? null : new URL(next, url);
    } catch {
      throw new Error('Invalid AVR pagination link.');
    }
  }
  return [...findings.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function issueMarker(finding) {
  const key = createHash('sha256').update(finding.id).digest('hex');
  return `<!-- sap-avr:hello-world:${key} -->`;
}

function text(value) {
  return value == null || value === '' ? 'Not provided' : String(value);
}

// Keep supplied content as normal text, without active HTML, Markdown, or mentions.
function plain(value) {
  return text(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/([\\`*_{}\[\]()#+.!|~-])/g, '\\$1').replace(/@/g, '@\u200b')
    .replace(/\r\n?/g, '\n').replace(/\n/g, '  \n');
}

// Recommendations contain advisory Markdown. Preserve fences and code exactly;
// neutralize HTML and mentions in prose without escaping its Markdown syntax.
function recommendationMarkdown(value) {
  const escapeProse = content => content.replace(/&/g, '&amp;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/@/g, '@\u200b');
  let fence = null;
  const lines = text(value).replace(/\r\n?/g, '\n').split('\n').map(line => {
    if (fence) {
      const closing = line.match(/^ {0,3}(`+|~+)\s*$/);
      if (closing && closing[1][0] === fence[0] && closing[1].length >= fence.length) fence = null;
      return line;
    }
    const opening = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (opening && (opening[1][0] !== '`' || !opening[2].includes('`'))) {
      fence = opening[1];
      return line;
    }
    let rendered = '';
    let offset = 0;
    for (const match of line.matchAll(/(`+)(?!`)(.*?)\1(?!`)/g)) {
      rendered += escapeProse(line.slice(offset, match.index)) + match[0];
      offset = match.index + match[0].length;
    }
    return rendered + escapeProse(line.slice(offset));
  });
  // A malformed advisory must not swallow the managed metadata into its code block.
  if (fence) lines.push(fence);
  return lines.join('\n');
}

function list(value) {
  return Array.isArray(value) && value.length ? value.map(text).join('\n') : 'None reported';
}

export function findingBody(finding) {
  const fields = [
    ['Application', finding.appName],
    ['Application ID', finding.appId],
    ['CVSS vector', finding.cvssVector],
    ['Source vulnerability ID', finding.sourceVulnerabilityId],
    ['Source', finding.sourceId],
    ['Advisory URL', finding.vulnerabilityUrl],
    ['First found', finding.firstFound],
    ['Last found', finding.lastFound],
    ['AVR ID', finding.id],
    ['Finding ID', finding.findingId],
  ];
  return [
    issueMarker(finding),
    `**Affected packages:** ${plain(list(finding.packageNames))}`,
    `**Vulnerabilities:** ${plain(list(finding.activeCves))}  \n**Severity:** ${severity(finding)} · **CVSS:** ${plain(finding.maxCvss)}`,
    `### Description\n\n${plain(finding.description)}`,
    `### Recommendation\n\n${recommendationMarkdown(finding.recommendation)}`,
    '<details>\n<summary>AVR details</summary>\n',
    ...fields.map(([label, value]) => `**${label}:** ${plain(value)}`),
    '</details>',
    'Beta-service finding; review applicability before taking action. Managed by the AVR PoC: keep investigation notes in comments. Recurring findings reopen issues; missing findings do not close them.',
  ].join('\n\n');
}

function severity(finding) {
  return ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].includes(finding.severity) ? finding.severity : 'UNKNOWN';
}

const LABELS = [
  { name: 'avr', color: '005A9C' },
  { name: 'security', color: 'B60205' },
  { name: 'app:hello-world', color: '1D76DB' },
  ...Object.entries({ critical: 'B60205', high: 'D93F0B', moderate: 'FBCA04', low: '0E8A16', unknown: 'BFD4F2' })
    .map(([level, color]) => ({ name: `severity:${level}`, color })),
];

function findingLabels(finding, issue) {
  const managed = new Set(LABELS.map(label => label.name));
  const manual = (issue?.labels || []).map(label => typeof label === 'string' ? label : label.name)
    .filter(name => !managed.has(name.toLowerCase()));
  return [...new Set([...manual, 'avr', 'security', 'app:hello-world', `severity:${severity(finding).toLowerCase()}`])];
}

function findingTitle(finding) {
  const advisory = text(finding.sourceVulnerabilityId).replace(/[\r\n\x00-\x1f]/g, ' ').slice(0, 100);
  const packages = Array.isArray(finding.packageNames) ? finding.packageNames.join(', ') : '';
  return `hello-world: ${advisory}${packages ? ` in ${packages}` : ''}`.replace(/[\r\n\x00-\x1f]/g, ' ').slice(0, 240);
}

export async function synchronizeIssues(findings, env, fetchImpl = fetch) {
  const repository = required(env, 'GITHUB_REPOSITORY');
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) throw new Error('Invalid GITHUB_REPOSITORY; expected owner/repository.');
  const token = required(env, 'GITHUB_TOKEN');
  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json',
  };
  const base = `${GITHUB_API}/repos/${repository}/issues`;
  const existing = [];
  for (let page = 1; ; page++) {
    if (page > 1000) throw new Error('GitHub issue pagination page limit exceeded.');
    const batch = await requestJson(`${base}?state=all&per_page=100&page=${page}`, { method: 'GET', headers }, fetchImpl, 'GitHub');
    if (!Array.isArray(batch)) throw new Error('GitHub returned an invalid issue list.');
    existing.push(...batch.filter(issue => !issue.pull_request));
    if (batch.length < 100) break;
  }
  // Preflight all matches before writing, including any accidental input duplicates.
  const unique = new Map(findings.map(finding => [finding.id, finding]));
  const operations = [...unique.values()].map(finding => {
    const marker = issueMarker(finding);
    const matches = existing.filter(issue => issue.body?.split('\n')[0].trim() === marker);
    if (matches.length > 1) throw new Error('Multiple GitHub issues already exist for an AVR finding; resolve them manually before retrying.');
    return { finding, issue: matches[0] };
  });
  const counts = { created: 0, updated: 0, reopened: 0, unchanged: 0 };
  if (operations.length) {
    const labelBase = `${GITHUB_API}/repos/${repository}/labels`;
    const known = new Set();
    for (let page = 1; ; page++) {
      if (page > 1000) throw new Error('GitHub label pagination page limit exceeded.');
      const batch = await requestJson(`${labelBase}?per_page=100&page=${page}`, { method: 'GET', headers }, fetchImpl, 'GitHub');
      if (!Array.isArray(batch)) throw new Error('GitHub returned an invalid label list.');
      for (const label of batch) known.add(label.name.toLowerCase());
      if (batch.length < 100) break;
    }
    const needed = new Set(operations.flatMap(({ finding }) => findingLabels(finding)));
    for (const label of LABELS.filter(label => needed.has(label.name) && !known.has(label.name))) {
      await requestJson(labelBase, { method: 'POST', headers, body: JSON.stringify(label) }, fetchImpl, 'GitHub');
    }
  }
  for (const { finding, issue } of operations) {
    const title = findingTitle(finding);
    const labels = findingLabels(finding, issue);
    const currentLabels = (issue?.labels || []).map(label => typeof label === 'string' ? label : label.name);
    const labelsChanged = JSON.stringify([...currentLabels].sort()) !== JSON.stringify([...labels].sort());
    const fullBody = findingBody(finding);
    // GitHub limits issue bodies to 65,536 characters. Bound unusually long
    // service content, keeping the marker. Full data remains in the JSON report.
    const body = fullBody.length > 60_000
      ? fullBody.slice(0, 60_000) + '\n\n[Issue body truncated; see JSON report for complete finding data.]'
      : fullBody;
    if (!issue) {
      const created = await requestJson(base, { method: 'POST', headers, body: JSON.stringify({ title, body, labels }) }, fetchImpl, 'GitHub');
      existing.push(created);
      counts.created++;
    } else if (issue.state === 'closed' || issue.title !== title || issue.body !== body || labelsChanged) {
      await requestJson(`${base}/${issue.number}`, {
        method: 'PATCH', headers,
        body: JSON.stringify({ title, body, labels, ...(issue.state === 'closed' ? { state: 'open' } : {}) }),
      }, fetchImpl, 'GitHub');
      counts[issue.state === 'closed' ? 'reopened' : 'updated']++;
    } else {
      counts.unchanged++;
    }
  }
  return counts;
}

export function summary(findings, counts) {
  const severities = new Map();
  for (const finding of findings) {
    const severity = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].includes(finding.severity) ? finding.severity : 'UNKNOWN';
    severities.set(severity, (severities.get(severity) || 0) + 1);
  }
  return [
    '# AVR: hello-world',
    `Retrieved at: ${new Date().toISOString()}`,
    `Matching findings: **${findings.length}**`,
    '| Severity | Findings |\n| --- | ---: |',
    ...['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'].map(severity => `| ${severity} | ${severities.get(severity) || 0} |`),
    counts ? `Issues: ${counts.created} created, ${counts.updated} updated, ${counts.reopened} reopened, ${counts.unchanged} unchanged.` : 'Issue synchronization has not completed.',
    '\nBeta service / non-production PoC. Findings require review. Missing findings do not close issues.',
  ].join('\n');
}

export async function main(env = process.env, fetchImpl = fetch) {
  // Validate GitHub configuration before contacting AVR.
  required(env, 'GITHUB_REPOSITORY');
  required(env, 'GITHUB_TOKEN');
  // Validate both service-key URLs before sending any credentials.
  serviceEndpoints(env);
  const token = await getAccessToken(env, fetchImpl);
  if (env.GITHUB_ACTIONS === 'true') console.log(`::add-mask::${token}`);
  const findings = await retrieveFindings(token, fetchImpl, env);
  const directory = resolve('reports');
  await mkdir(directory, { recursive: true });
  await writeFile(resolve(directory, 'hello-world-findings.json'), JSON.stringify({ value: findings }, null, 2) + '\n');
  await writeFile(resolve(directory, 'hello-world-report.md'), summary(findings) + '\n\n' + findings.map(findingBody).join('\n\n---\n\n') + '\n');
  const counts = await synchronizeIssues(findings, env, fetchImpl);
  const result = summary(findings, counts);
  await writeFile(resolve(directory, 'summary.md'), result + '\n');
  if (env.GITHUB_STEP_SUMMARY) await appendFile(env.GITHUB_STEP_SUMMARY, result + '\n');
  console.log(`AVR synchronization complete: ${findings.length} hello-world findings; ${JSON.stringify(counts)}.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
