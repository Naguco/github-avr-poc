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

// Render service-supplied content literally: no active HTML, mentions, or
// embedded Markdown links/images from vulnerability descriptions.
function literal(value, maxLength = 20_000) {
  const content = text(value).slice(0, maxLength);
  const runs = content.match(/`+/g) || [];
  const fence = '`'.repeat(Math.max(3, ...runs.map(run => run.length + 1)));
  return `${fence}text\n${content}\n${fence}${text(value).length > maxLength ? '\n[Truncated; see JSON report for complete content.]' : ''}`;
}

function list(value) {
  return Array.isArray(value) && value.length ? value.map(text).join('\n') : 'None reported';
}

export function findingBody(finding) {
  const fields = [
    ['Application', finding.appName],
    ['Application ID', finding.appId],
    ['Severity', finding.severity || 'UNKNOWN'],
    ['CVSS score', finding.maxCvss],
    ['CVSS vector', finding.cvssVector],
    ['Affected packages', list(finding.packageNames)],
    ['Active vulnerability identifiers', list(finding.activeCves)],
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
    '# Application vulnerability report finding',
    '> Beta-service finding. Review applicability and remediation before taking action.',
    ...fields.map(([label, value]) => `## ${label}\n${literal(value, 1000)}`),
    `## Description\n${literal(finding.description, 5000)}`,
    `## Recommendation\n${literal(finding.recommendation)}`,
    '---\nManaged by the AVR PoC. This body is refreshed on each synchronization. Keep investigation notes in comments. Closed issues are reopened when their finding is returned again; missing findings are not automatically closed.',
  ].join('\n\n');
}

function findingTitle(finding) {
  const severity = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].includes(finding.severity) ? finding.severity : 'UNKNOWN';
  const advisory = text(finding.sourceVulnerabilityId).replace(/[\r\n\x00-\x1f]/g, ' ').slice(0, 100);
  return `[AVR][${severity}] hello-world: ${advisory}`;
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
  for (const { finding, issue } of operations) {
    const title = findingTitle(finding);
    const fullBody = findingBody(finding);
    // GitHub limits issue bodies to 65,536 characters. Bound unusually long
    // service content (including generated code fences), keeping the marker.
    const body = fullBody.length > 60_000
      ? fullBody.slice(0, 60_000) + '\n\n[Issue body truncated; see JSON report for complete finding data.]'
      : fullBody;
    if (!issue) {
      const created = await requestJson(base, { method: 'POST', headers, body: JSON.stringify({ title, body }) }, fetchImpl, 'GitHub');
      existing.push(created);
      counts.created++;
    } else if (issue.state === 'closed' || issue.title !== title || issue.body !== body) {
      await requestJson(`${base}/${issue.number}`, {
        method: 'PATCH', headers,
        body: JSON.stringify({ title, body, ...(issue.state === 'closed' ? { state: 'open' } : {}) }),
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
