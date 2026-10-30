import assert from 'node:assert/strict';
import test from 'node:test';
import {
  APP_NAME, filterFindings, findingBody,
  getAccessToken, issueMarker, main, requestJson, retrieveFindings, serviceEndpoints, synchronizeIssues as syncIssues,
} from '../scripts/fetch-findings.mjs';

const env = {
  AVR_BASE_URL: 'https://avr.example', AVR_UAA_URL: 'https://auth.example',
  AVR_CLIENT_ID: 'test-client', AVR_CLIENT_SECRET: 'test-secret',
  GITHUB_REPOSITORY: 'example/poc', GITHUB_TOKEN: 'test-github-token',
};
const { findingsUrl: FINDINGS_URL, tokenUrl: TOKEN_URL } = serviceEndpoints(env);
const finding = {
  id: 'osv-scanner-synthetic-finding', appName: APP_NAME, appId: 'synthetic-app',
  severity: 'HIGH', maxCvss: '7.50', packageNames: ['pkg:npm/example@1.0.0'],
  activeCves: ['CVE-2026-0000'], sourceVulnerabilityId: 'GHSA-example',
  description: 'Synthetic test finding', recommendation: 'Upgrade the affected component.',
};
const response = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => data });
const labelNames = ['avr', 'security', 'app:hello-world', ...['critical', 'high', 'moderate', 'low', 'unknown'].map(level => `severity:${level}`)];
// Existing issue-lifecycle tests assume repository labels already exist.
function synchronizeIssues(findings, environment, fetchImpl) {
  return syncIssues(findings, environment, (url, options) => url.includes('/labels?')
    ? Promise.resolve(response(labelNames.map(name => ({ name }))))
    : fetchImpl(url, options));
}

test('service-key base URLs build customer-specific endpoints and normalize trailing slashes', () => {
  assert.deepEqual(serviceEndpoints({
    AVR_BASE_URL: 'https://customer-avr.example/', AVR_UAA_URL: 'https://customer-auth.example///',
  }), {
    findingsUrl: 'https://customer-avr.example/api/v1/provider/Findings',
    tokenUrl: 'https://customer-auth.example/oauth/token',
  });
  for (const name of ['AVR_BASE_URL', 'AVR_UAA_URL']) {
    assert.throws(() => serviceEndpoints({ ...env, [name]: '' }), /Missing required/);
    for (const value of ['not-a-url', 'http://unsafe.example', 'https://user:secret@unsafe.example',
      'https://unsafe.example?secret=hidden', 'https://unsafe.example#fragment']) {
      assert.throws(() => serviceEndpoints({ ...env, [name]: value }), error => {
        assert.match(error.message, new RegExp(`Invalid ${name}`));
        assert.ok(!error.message.includes(value));
        return true;
      });
    }
  }
});

test('invalid service URLs fail before credentials or bearer tokens are sent', async () => {
  const noRequest = async () => { assert.fail('No HTTP request should be made'); };
  await assert.rejects(getAccessToken({ ...env, AVR_UAA_URL: 'http://unsafe.example' }, noRequest), /Invalid AVR_UAA_URL/);
  await assert.rejects(retrieveFindings('token', noRequest, { ...env, AVR_BASE_URL: 'http://unsafe.example' }), /Invalid AVR_BASE_URL/);
  await assert.rejects(main({ ...env, AVR_BASE_URL: '' }, noRequest), /Missing required.*AVR_BASE_URL/);
});

test('OAuth sends form-encoded client credentials and optional scope', async () => {
  const token = await getAccessToken({ ...env, AVR_SCOPE: 'test-scope' }, async (url, options) => {
    assert.equal(url, TOKEN_URL);
    assert.equal(options.method, 'POST');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers['Content-Type'], 'application/x-www-form-urlencoded');
    const body = new URLSearchParams(options.body);
    assert.equal(body.get('client_id'), env.AVR_CLIENT_ID);
    assert.equal(body.get('client_secret'), env.AVR_CLIENT_SECRET);
    assert.equal(body.get('grant_type'), 'client_credentials');
    assert.equal(body.get('scope'), 'test-scope');
    return response({ access_token: 'synthetic-token' });
  });
  assert.equal(token, 'synthetic-token');
});

test('OAuth rejects missing credentials or missing token', async () => {
  await assert.rejects(getAccessToken({}), /Missing required/);
  await assert.rejects(getAccessToken(env, async () => response({})), /access_token/);
});

test('exact filter excludes hello-world-srv and retains unscored findings', () => {
  const unknown = { ...finding, id: 'malicious-package', severity: '', maxCvss: null, activeCves: [] };
  assert.deepEqual(filterFindings([finding, { ...finding, appName: 'hello-world-srv' }, { ...finding, appName: 'other' }, unknown]), [finding, unknown]);
  assert.deepEqual(filterFindings([]), []);
  assert.throws(() => filterFindings(undefined), /value array/);
  assert.throws(() => filterFindings([null]), /value array/);
  assert.match(findingBody(unknown), /UNKNOWN/);
  assert.match(findingBody(unknown), /None reported/);
});

test('retrieval follows pagination, filters all pages, and deduplicates IDs', async () => {
  const calls = [];
  const result = await retrieveFindings('synthetic-token', async (url, options) => {
    calls.push(url);
    assert.equal(options.method, 'GET');
    assert.equal(options.headers.Authorization, 'Bearer synthetic-token');
    return response(calls.length === 1
      ? { value: [finding, { ...finding, appName: 'other' }], '@odata.nextLink': '?$skiptoken=next' }
      : { value: [finding, { ...finding, id: 'second' }] });
  }, env);
  assert.equal(calls.length, 2);
  assert.equal(new URL(calls[1]).origin, new URL(FINDINGS_URL).origin);
  assert.equal(result.length, 2);
});

test('retrieval rejects unsafe links before forwarding bearer token', async () => {
  let calls = 0;
  await assert.rejects(retrieveFindings('token', async () => {
    calls++;
    return response({ value: [], '@odata.nextLink': 'https://untrusted.example/findings' });
  }, env), /unsafe AVR/);
  assert.equal(calls, 1);
});

test('optional OData filter still enforces exact local matching', async () => {
  const result = await retrieveFindings('token', async (url) => {
    assert.equal(new URL(url).searchParams.get('$filter'), "appName eq 'hello-world'");
    return response({ value: [finding, { ...finding, appName: 'hello-world-srv' }] });
  }, { ...env, AVR_SERVER_FILTER: 'true' });
  assert.deepEqual(result, [finding]);
});

test('retrieval rejects pagination loops and missing stable IDs', async () => {
  await assert.rejects(retrieveFindings('token', async () => response({ value: [], '@odata.nextLink': FINDINGS_URL }), env), /pagination loop/);
  await assert.rejects(retrieveFindings('token', async () => response({ value: [{ appName: APP_NAME }] }), env), /stable id/);
  await assert.rejects(retrieveFindings('token', async () => response({ value: [], '@odata.nextLink': 5 }), env), /pagination link/);
});

test('HTTP, invalid JSON and network errors fail without exposing response content', async () => {
  await assert.rejects(requestJson(FINDINGS_URL, {}, async () => response({ secret: 'hidden' }, 401), 'AVR'), /^Error: AVR request failed: HTTP 401\.$/);
  await assert.rejects(requestJson(FINDINGS_URL, {}, async () => ({ ok: true, json: async () => { throw new Error('secret'); } })), /invalid JSON/);
  await assert.rejects(requestJson(FINDINGS_URL, {}, async () => { throw new Error('secret'); }), /network error/);
});

test('new findings create one issue each, including duplicate input IDs', async () => {
  let writes = 0;
  const counts = await synchronizeIssues([finding, finding], env, async (_url, options) => {
    if (options.method === 'GET') return response([]);
    assert.equal(options.method, 'POST');
    const body = JSON.parse(options.body);
    assert.ok(body.body.startsWith(issueMarker(finding)));
    writes++;
    return response({ number: 1, ...body, state: 'open' }, 201);
  });
  assert.equal(writes, 1);
  assert.equal(counts.created, 1);
});

test('identical reruns do not write or create duplicate issues', async () => {
  let existing;
  await synchronizeIssues([finding], env, async (_url, options) => {
    if (options.method === 'GET') return response([]);
    existing = { number: 1, ...JSON.parse(options.body), state: 'open' };
    return response(existing, 201);
  });
  const counts = await synchronizeIssues([finding], env, async (_url, options) => {
    assert.equal(options.method, 'GET');
    return response([existing]);
  });
  assert.equal(counts.unchanged, 1);
});

test('existing open issues are updated and closed issues are reopened', async () => {
  for (const state of ['open', 'closed']) {
    const counts = await synchronizeIssues([finding], env, async (url, options) => {
      if (options.method === 'GET') return response([{ number: 12, body: issueMarker(finding), state }]);
      assert.ok(url.endsWith('/issues/12'));
      assert.equal(options.method, 'PATCH');
      const patch = JSON.parse(options.body);
      assert.equal(patch.state, state === 'closed' ? 'open' : undefined);
      return response({ number: 12, ...patch });
    });
    assert.equal(counts[state === 'closed' ? 'reopened' : 'updated'], 1);
    assert.equal(counts.created, 0);
  }
});

test('GitHub pagination includes closed issues and excludes pull requests', async () => {
  let reads = 0;
  const counts = await synchronizeIssues([finding], env, async (url, options) => {
    if (options.method === 'GET') {
      reads++;
      assert.ok(url.includes('state=all'));
      if (reads === 1) return response(Array.from({ length: 100 }, (_, number) => ({ number, body: issueMarker(finding), pull_request: {} })));
      assert.ok(url.endsWith('page=2'));
      return response([{ number: 101, body: issueMarker(finding), state: 'closed' }]);
    }
    assert.ok(url.endsWith('/101'));
    return response({});
  });
  assert.equal(reads, 2);
  assert.equal(counts.reopened, 1);
});

test('preexisting duplicates fail preflight without any issue writes', async () => {
  await assert.rejects(synchronizeIssues([finding], env, async (_url, options) => {
    assert.equal(options.method, 'GET');
    return response([1, 2].map(number => ({ number, body: issueMarker(finding), state: 'open' })));
  }), /Multiple GitHub issues/);
});

test('empty results never close existing issues', async () => {
  const counts = await synchronizeIssues([], env, async (_url, options) => {
    assert.equal(options.method, 'GET');
    return response([{ number: 1, body: issueMarker(finding), state: 'open' }]);
  });
  assert.equal(counts.created, 0);
  assert.equal(counts.updated, 0);
});

test('compact summary and description remain escaped normal text', () => {
  const body = findingBody({ ...finding, description: '```\n@someone <script>test</script>\n```' });
  assert.ok(!body.includes('```'));
  assert.ok(!body.includes('<script>'));
  assert.ok(!body.includes('@someone'));
  assert.ok(body.includes('&lt;script&gt;test&lt;/script&gt;'));
  assert.ok(body.includes('<summary>AVR details</summary>'));
  assert.ok(body.startsWith(issueMarker(finding)));
  assert.ok(findingBody({ ...finding, recommendation: 'a'.repeat(25_000) }).includes('a'.repeat(25_000)));
  assert.ok(!body.includes('| ---'));
});

test('recommendations preserve Markdown, code fences, and code contents', () => {
  const recommendation = [
    '## Summary', '', 'Review **size limits** and `config.maxBodyLength`.', '',
    '[Advisory](https://example.com/advisory)', '', '```js',
    'if (size < limit && enabled) { console.log("@someone <script>"); }', '```', '',
    '~~~bash', 'node --max-old-space-size=100 poc.js', '~~~', '',
    '1. Enforce limits.', '2. Stream decoding.',
  ].join('\n');
  const body = findingBody({ ...finding, recommendation });
  assert.ok(body.includes(`### Recommendation\n\n${recommendation}\n\n<details>`));
  assert.ok(!body.includes('\\`'));
});

test('recommendation prose neutralizes HTML and mentions but preserves inline code', () => {
  const body = findingBody({ ...finding, recommendation: '<script>test</script> @someone\n`a < b && @example`' });
  assert.ok(body.includes('&lt;script&gt;test&lt;/script&gt; @\u200bsomeone'));
  assert.ok(body.includes('`a < b && @example`'));
});

test('unclosed recommendation fences are closed before AVR metadata', () => {
  const body = findingBody({ ...finding, recommendation: '````js\nconst example = "```";' });
  assert.ok(body.includes('const example = "```";\n````\n\n<details>'));
});

test('GitHub issue write failures fail synchronization', async () => {
  await assert.rejects(synchronizeIssues([finding], env, async (_url, options) => response(options.method === 'GET' ? [] : {}, options.method === 'GET' ? 200 : 403)), /GitHub request failed: HTTP 403/);
});

test('severity and timestamps can change without changing issue identity', async () => {
  const changed = { ...finding, severity: 'CRITICAL', lastFound: '2026-10-30T00:00:00.000Z' };
  assert.equal(issueMarker(finding), issueMarker(changed));
  const counts = await synchronizeIssues([changed], env, async (url, options) => {
    if (options.method === 'GET') return response([{ number: 15, body: findingBody(finding), title: 'Previous title', state: 'open' }]);
    assert.equal(options.method, 'PATCH');
    assert.ok(url.endsWith('/15'));
    assert.ok(JSON.parse(options.body).labels.includes('severity:critical'));
    assert.ok(!JSON.parse(options.body).title.includes('[AVR]'));
    assert.ok(JSON.parse(options.body).body.includes('2026\\-10\\-30'));
    return response({});
  });
  assert.equal(counts.updated, 1);
  assert.equal(counts.created, 0);
});

test('missing repository labels are created and attached to new issues', async () => {
  const createdLabels = [];
  await syncIssues([finding], env, async (url, options) => {
    if (options.method === 'GET') return response([]);
    const body = JSON.parse(options.body);
    if (url.endsWith('/labels')) {
      createdLabels.push(body.name);
      assert.match(body.color, /^[0-9A-F]{6}$/);
      return response(body, 201);
    }
    assert.deepEqual(body.labels, ['avr', 'security', 'app:hello-world', 'severity:high']);
    assert.equal(body.title, 'hello-world: GHSA-example in pkg:npm/example@1.0.0');
    return response({ number: 1, ...body, state: 'open' }, 201);
  });
  assert.deepEqual(createdLabels, ['avr', 'security', 'app:hello-world', 'severity:high']);
});

test('severity label updates preserve manually added labels', async () => {
  await synchronizeIssues([{ ...finding, severity: 'LOW' }], env, async (_url, options) => {
    if (options.method === 'GET') return response([{
      number: 1, body: findingBody(finding), state: 'open',
      labels: ['avr', 'security', 'app:hello-world', 'severity:high', 'investigating'].map(name => ({ name })),
    }]);
    const labels = JSON.parse(options.body).labels;
    assert.ok(labels.includes('investigating'));
    assert.ok(labels.includes('severity:low'));
    assert.ok(!labels.includes('severity:high'));
    return response({});
  });
});

test('label creation errors fail before any issue writes', async () => {
  await assert.rejects(syncIssues([finding], env, async (url, options) => {
    if (options.method === 'GET') return response([]);
    assert.ok(url.endsWith('/labels'));
    return response({}, 403);
  }), /GitHub request failed: HTTP 403/);
});
