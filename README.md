# SAP Application Vulnerability Report → GitHub Issues

This PoC shows how to read findings from the Application Vulnerability Report (AVR) service of the SAP Business AI Platform (BAIP) and create GitHub issues for them. It checks only the application named `hello-world`, every Tuesday and Friday at midnight UTC.

The instructions below explain how to try it in your own test repository and non-production SAP BTP subaccount.

## Important disclaimers

> This is a beta service available on SAP BTP for subaccounts in trial and enterprise accounts. For more information, see Important Disclaimers and Legal Information.

For now, test AVR only in non-production subaccounts. Set the **Beta Enabled** flag on the subaccount, then follow SAP's instructions to enable the service and configure access.

This code is provided as an example. It is not recommended for production use without security, operational, and legal review. The service is in beta, so its availability and API may change. Before using it, read [SAP's AVR documentation and its Important Disclaimers and Legal Information](https://help.sap.com/docs/application-vulnerability-report/application-vulnerability-report-e02c6e1a86544ce981810c8c8a12e750/what-is-application-vulnerability-report).

A reported vulnerability still needs to be checked against how your application uses the affected component. AVR does not replace a full security assessment, and this script does not apply fixes or run any code included in a finding.

## Why this example

Applications depend on open-source packages, and new vulnerabilities are reported regularly. AVR checks for publicly known vulnerabilities based on Common Vulnerabilities and Exposures (CVEs) in an SAP BTP landscape. Checking regularly gives developers a chance to review and fix them sooner, before someone exploits them.

The service is currently described as [free within BAIP](https://discovery-center.cloud.sap/serviceCatalog/application-vulnerability-report?service_plan=standard-plan&region=europe(frankfurt)&commercialModel=btpea&provider=aws&tab=service_plan). Check SAP's current terms and availability for your account before relying on that. With more CVEs to review and AI agents helping teams write code faster, a scheduled check is worth trying. This PoC puts the findings in GitHub Issues so they can be reviewed alongside other development work. It does not replace dependency updates or other security checks.

## Files in this example

| File | Responsibility |
| --- | --- |
| `.github/workflows/avr-findings.yml` | Scheduled/manual execution, credentials, permissions, concurrency, artifacts |
| `scripts/fetch-findings.mjs` | OAuth, AVR retrieval, exact filtering, reports, issue synchronization |
| `tests/fetch-findings.test.mjs` | Synthetic, mock-based tests; no real credentials or API requests |
| `.gitignore` | Keeps local credentials and reports out of Git |

The script and tests use Node.js 24's built-in APIs. You do not need to run `npm install` or deploy an application.

## Before you start

1. An eligible SAP BTP trial or enterprise subaccount, **not production**, with **Beta Enabled** set.
2. AVR enabled for your landscape [according to SAP's current instructions](https://help.sap.com/docs/application-vulnerability-report/application-vulnerability-report-e02c6e1a86544ce981810c8c8a12e750/initial-setup).
3. Your own AVR service instance and service key, with credentials allowed to read provider findings. [You need to set these up in SAP BAIP](https://help.sap.com/docs/application-vulnerability-report/application-vulnerability-report-e02c6e1a86544ce981810c8c8a12e750/authentication); the script does not create services, keys, or permissions.
4. A private GitHub repository with Issues and Actions enabled, and permission to add repository secrets. Findings contain vulnerability and landscape information that should not be published unintentionally.
5. Access to the SAP endpoints from the GitHub-hosted runner. If your organization restricts that access, use a runner that meets its network and security requirements.

## Add the files to GitHub

Copy the files, including the hidden `.github` directory, into your repository. Commit and push them to the default branch, which GitHub uses for scheduled workflows. The schedule will not run from this local folder.

Before enabling the workflow, review who can change workflow files or access repository secrets. Do not add a pull-request trigger that exposes SAP BAIP credentials to untrusted code.

## Configure authentication

Create a service key for your AVR service instance in your non-production subaccount. In the SAP BTP cockpit, open **Services → Instances and Subscriptions**, select the AVR instance, and create a service key. Follow SAP's current setup instructions if you still need to create the instance or configure access.

Open the key and take the following values from its JSON. Use your own key, not the example URLs below: the service and authentication hosts can differ between keys.

In **Settings → Secrets and variables → Actions → Secrets**, add:

| Repository secret | Value |
| --- | --- |
| `AVR_CLIENT_ID` | `uaa.clientid` from your service key |
| `AVR_CLIENT_SECRET` | `uaa.clientsecret` from your service key |

Under the **Variables** tab, add:

| Repository variable | Value |
| --- | --- |
| `AVR_BASE_URL` | `uri` from your service key |
| `AVR_UAA_URL` | `uaa.url` from your service key |

Copy the base URLs as they appear in the key. The script appends `/api/v1/provider/Findings` to `AVR_BASE_URL` and `/oauth/token` to `AVR_UAA_URL`. Do not append those paths yourself. Use `uaa.url` for authentication, not `uaa.sburl` or `uaa.apiurl`.

Keep the service key private. Do not commit its JSON, paste it into an issue, or include it in logs. Store the client credentials as secrets, not repository variables.

If your OAuth client requires a scope, add it as the repository variable `AVR_SCOPE`. Otherwise, leave that variable unset.

For example, a key with `uaa.url` set to `https://app-vuln-report.authentication.eu10.hana.ondemand.com` produces this token endpoint:

```text
https://app-vuln-report.authentication.eu10.hana.ondemand.com/oauth/token
```

The script sends a POST with `Content-Type: application/x-www-form-urlencoded`:

```text
grant_type=client_credentials
client_id=<client ID>
client_secret=<client secret>
```

The script uses the returned `access_token` in the AVR request's `Authorization: Bearer …` header. It gets a new token for each run, masks it in Actions logs, and leaves it out of the reports. Client credentials are not logged either.

This example sends the client credentials in the POST body. If your client requires X509 instead, change `getAccessToken()` and its tests before running it.

GitHub supplies `github.token` automatically, so you do not need a personal access token for the workflow. It requests `contents: read` and `issues: write`. Your organization's Actions policy must allow it to write issues.

## Schedule and application filter

```yaml
on:
  schedule:
    - cron: '0 0 * * 2,5'
  workflow_dispatch:
```

The schedule is **00:00 UTC on Tuesday and Friday** and does not change with daylight saving time. GitHub may delay or drop scheduled runs when busy, especially at the start of an hour, so do not expect execution at exactly midnight. GitHub may also disable schedules in public repositories after prolonged inactivity.

The findings endpoint is built from your service key's `uri`. For example, `https://application-vulnerability-report.cfapps.eu10-005.hana.ondemand.com` produces:

```text
https://application-vulnerability-report.cfapps.eu10-005.hana.ondemand.com/api/v1/provider/Findings
```

The script retrieves the findings and filters each page of the response:

```js
value.filter(item => item.appName === 'hello-world')
```

This is an exact, case-sensitive match. It excludes `hello-world-srv` and every other application name. If more than one deployed application is named `hello-world`, their findings will all be included. Add an `appId` check if you want to select a single deployment.

SAP's documentation describes OData requests, but this PoC received HTTP 400 when using the application filter below. The workflow therefore sets `AVR_SERVER_FILTER: 'false'` and filters locally. If you confirm that your endpoint supports this filter, you can set `AVR_SERVER_FILTER: 'true'` to additionally send:

```text
$filter=appName eq 'hello-world'
```

The script still checks the application name locally when this option is enabled. If the endpoint rejects the OData filter, the run fails. Set the option back to `'false'` to use local filtering only.

Both configured base URLs must use HTTPS, without embedded credentials, query strings, or fragments. The script follows `@odata.nextLink` and rejects links outside the configured AVR service origin, credentials embedded in links, fragments, loops, or more than 1,000 pages. HTTP redirects are rejected for both SAP and GitHub requests. A GET carries no request body.

## Try a manual run

Open **Actions → AVR findings for hello-world → Run workflow**. Choose the default branch, run it, and inspect the job summary and repository's Issues tab.

The job runs the tests, retrieves the findings, saves the filtered reports, and creates or updates issues. Finding vulnerabilities does not fail the job; it creates issues for review. The job fails if authentication, response parsing, pagination, or a GitHub request fails.

## How issues are created and updated

The script uses each finding's AVR `id` to find its issue on later runs. It does not match by title or CVE, since the same CVE can appear in several findings and the severity may change.

The first line of every managed issue body contains:

```html
<!-- sap-avr:hello-world:<SHA-256 of the AVR id> -->
```

| Finding/issue state | Action |
| --- | --- |
| No matching issue | Create an issue |
| Existing open issue, changed content or managed labels | Update its title, body, and labels |
| Existing open issue, identical content and labels | No write |
| Existing closed issue, finding returned | Reopen and refresh the same issue |
| Finding absent from response | Leave existing issue unchanged |
| Multiple issues with the same marker | Fail before writing; require manual resolution |

Before writing, the script reads the repository's open and closed issues, including all pages of results. It ignores pull requests and processes a repeated AVR ID only once. GitHub's workflow concurrency setting keeps two runs of this workflow from updating issues at the same time.

Leave the marker in place. If you remove it or delete the issue, the script may create another issue the next time it sees that finding. A change to the finding's ID in AVR can also result in a new issue.

Do not run a separate copy of the script against the same repository while the workflow is running. GitHub's concurrency setting does not coordinate local scripts or workflows using a different concurrency group.

Put investigation notes in issue comments. The script replaces the issue body when it refreshes a finding, so edits there will be lost. If you close an issue but AVR still returns the finding, the script reopens it. This PoC has no ignore list or way to record accepted risks, and it does not close issues automatically.

Each issue includes the application, affected packages, severity, CVSS score, vulnerability identifiers, advisory reference, timestamps, description, and recommendation. Findings with no CVE or score are included too. For example, a malicious-package report may have neither. An empty severity is shown as `UNKNOWN`.

Titles use `hello-world: <advisory> in <packages>`. The body starts with affected packages, vulnerability identifiers, severity, and CVSS, followed by the description and recommendation. The remaining metadata is under an expandable **AVR details** section. Everything is normal text, without code blocks or tables.

The script adds `avr`, `security`, `app:hello-world`, and one `severity:` label (`critical`, `high`, `moderate`, `low`, or `unknown`). It creates missing labels in the repository without changing existing label colors. When severity changes, it replaces the old severity label and keeps unrelated labels you added manually. The GitHub token must also have permission to create labels; the workflow's `issues: write` permission covers this.

Descriptions and recommendations retain their content as normal text. HTML, Markdown formatting, and mentions from the service are escaped so they do not become active content. The advisory URL is provided as text. Only unusually large issue bodies are truncated to stay below GitHub's size limit; the JSON report retains complete finding data. Recommendations are not run or automatically applied. Existing managed issues adopt this format on the next synchronization; you do not need to delete them first.

## Download the reports

Successful runs upload `hello-world-avr-reports-<run ID>` with **7-day retention**:

- `hello-world-findings.json`: `{ "value": [...] }`, containing only matching findings and their original fields.
- `hello-world-report.md`: filtered findings, including recommendations.
- `summary.md`: counts by severity and issue creation/update/reopening totals.

A summary with two test findings might look like this:

```text
Matching findings: 2
HIGH: 1
UNKNOWN: 1
Issues: 2 created, 0 updated, 0 reopened, 0 unchanged.
```

If a GitHub request fails, the reports may still be uploaded even though the workflow has failed. Some issues may already have been created or updated. On a rerun, the script checks their markers before creating anything else. Check the workflow result rather than assuming that downloaded reports mean all issues were updated.

The seven-day retention applies only to artifacts, not issues. Anyone who can read the repository can read its issues. The JSON report also contains the account, organization, space, and application details returned by SAP, so check who has access before enabling the workflow. The script does not commit reports to Git.

## Run locally

Run tests without contacting SAP or GitHub:

```bash
node --test
```

To try the script locally, set `AVR_BASE_URL`, `AVR_UAA_URL`, `AVR_CLIENT_ID`, and `AVR_CLIENT_SECRET` using the service-key mapping above. Also set `GITHUB_REPOSITORY` (`owner/repository`) and `GITHUB_TOKEN` through your usual secret-management tools. Unlike the workflow, a local run needs you to supply a GitHub token with permission to read, create, and update repository issues. Set `AVR_SCOPE` only if your client requires it. Then run:

```bash
node scripts/fetch-findings.mjs
```

**This command creates, updates, and reopens real issues.** Run against a private test repository only. Do not put credentials into shell commands/history or committed files. A `.env` file is not loaded automatically. Output goes to the ignored `reports/` directory.

## If a run fails

An OAuth 400 or 401 response usually means you need to check the credentials, token endpoint, client authentication method, or scope. An AVR 401 or 403 response means you should also check the client's permission to read provider findings and whether the service setup is complete. Getting a token does not necessarily grant access to the endpoint.

For a GitHub 403 response, check the repository's issue permissions, your organization's Actions policy, repository restrictions, and rate limits.

If the run succeeds with no findings, check the deployed application's exact name. An empty response does not close existing issues.

If the script reports duplicate markers, consolidate the issues manually and remove the marker from the redundant issue. Just closing it will not help, because the script checks closed issues too.

## What this PoC does not cover

This PoC does not provision SAP resources, refresh tokens mid-run, retry failed writes automatically, implement suppression, auto-close issues, or deduplicate changed service IDs. The application name is fixed to `hello-world`; the SAP base URLs come from your service key. GitHub integration targets `github.com`; adapt it for GitHub Enterprise Server if required.

If you later want to use this beyond a test, first check whether SAP supports production use of AVR at that time. You will also need to review permissions, which finding data to retain, retries and rate limits, credential rotation, monitoring, and how to handle resolved or accepted findings. Pin the workflow actions to reviewed commit SHAs rather than relying on version tags.
