/* ============================================================
   SECURITY MISCONFIGURATION
   Subdomain Takeover — a dangling DNS record pointing at a
   third-party resource nobody owns anymore. Full checklists
   included, not condensed summaries.
   ============================================================ */

var SECURITY_MISCONFIG = [

/* ---------------- 1. SUBDOMAIN TAKEOVER ---------------- */
{
  id: "subdomain-takeover",
  title: "Subdomain Takeover",
  category: "Security Misconfiguration",
  severity: "high",
  descriptionHTML: `
    <p>A subdomain takeover happens when a DNS record (almost always a <code>CNAME</code>, sometimes an <code>NS</code> delegation) still points at a third-party resource — a cloud host, a static site platform, a SaaS integration — that has since been deleted or deprovisioned, while the DNS record itself was never cleaned up. If that provider lets <em>anyone</em> register the now-empty resource name, an attacker can claim it and effectively take control of content served under the organization's own trusted subdomain.</p>
    <p>The critical distinction the whole testing process hinges on: <strong>a dangling CNAME alone is not proof of takeover.</strong> You need the full chain — dangling record → specific provider identified → resource confirmed gone → resource confirmed claimable by someone else.</p>
  `,
  impactHTML: `
    <p>Impact depends entirely on what the subdomain is trusted for, not just that it exists. Walk this checklist once a takeover is confirmed:</p>
    <div class="checklist">
      <ul>
        <li>Phishing under a trusted subdomain</li>
        <li>Malicious content hosted under trusted origin</li>
        <li>Brand impersonation</li>
        <li>OAuth redirect abuse</li>
        <li>Password-reset link abuse</li>
        <li>CORS trust relationship abuse</li>
        <li>Cookie scope implications</li>
        <li>CSP trust relationship</li>
        <li>Script/resource trust</li>
        <li>Webhook trust</li>
        <li>SSO integration impact</li>
        <li>API integration impact</li>
        <li>Search-engine reputation impact</li>
      </ul>
    </div>
    <p>A forgotten <code>blog.target.com</code> is a very different finding from <code>auth.target.com</code> or <code>cdn.target.com</code> — always identify what currently references the hostname before scoring it.</p>
  `,
  severityHTML: `
    <p><strong>Medium</strong> for a forgotten, low-traffic subdomain with no onward trust relationships. <strong>High → Critical</strong> when the hostname sits in an OAuth redirect allowlist, a CORS/CSP trust list, or is the source of a script/resource the main app actually loads. Always check the impact checklist above before assigning severity — that's what separates a cosmetic finding from a serious one.</p>
  `,
  stepsHTML: `
    <h4 style="margin-top:0">1. Build the subdomain inventory</h4>
    <p>Passive sources first — Certificate Transparency logs are the highest-signal source since certs often reveal hostnames nobody links to from the main site:</p>
    <pre><code>subfinder -d target.com -silent -o subs.txt
amass enum -passive -d target.com -o amass-subs.txt</code></pre>
    <p>Also pull historical DNS (<code>securitytrails.com</code>, <code>dnsdumpster.com</code>), search JS files and public source repos for hardcoded hostnames (<code>.target.com</code>, <code>CNAME</code>, <code>custom_domain</code>, <code>base_url</code>, <code>redirect_uri</code>, <code>cdn_url</code>), and check search-engine indexes.</p>
    <div class="checklist">
      <div class="checklist-title">☐ Environment names worth including in wordlists</div>
      <ul>
        <li><code>dev</code></li><li><code>development</code></li><li><code>test</code></li><li><code>testing</code></li>
        <li><code>qa</code></li><li><code>uat</code></li><li><code>stage</code></li><li><code>staging</code></li>
        <li><code>preprod</code></li><li><code>prod</code></li><li><code>production</code></li>
        <li><code>sandbox</code></li><li><code>demo</code></li><li><code>beta</code></li><li><code>alpha</code></li>
      </ul>
    </div>

    <h4>2. Resolve and inspect every DNS record type</h4>
    <pre><code>dnsx -l subs.txt -silent -resp -a -aaaa -cname -ns</code></pre>
    <div class="checklist single">
      <div class="checklist-title">☐ DNS record checklist — check all of these per hostname</div>
      <ul>
        <li><code>A</code></li><li><code>AAAA</code></li><li><code>CNAME</code></li><li><code>NS</code></li>
        <li><code>MX</code></li><li><code>TXT</code></li><li><code>CAA</code></li>
      </ul>
      <p style="margin:8px 0 0;font-size:0.82rem;color:var(--ink-faint);">Highest-priority takeover candidates are usually <code>CNAME</code> and <code>NS</code>, but don't ignore unusual delegation configurations — an <code>A</code> + <code>CNAME</code> both present on the same hostname indicates a configuration problem worth a closer look.</p>
    </div>
    <p>For each candidate, record: hostname, record type, record value, TTL, provider, current resolution, HTTP response.</p>

    <h4>3. Fingerprint the target service</h4>
    <pre><code>curl -sI https://candidate.target.com</code></pre>
    <p>Read the <code>Server</code> header, the response body, and the status code. The key question is always: <strong>why</strong> does this say "not found" — is that a provider-specific "this app doesn't exist, register it here" message, or just a generic web server error?</p>
    <p><strong>A plain, unbranded <code>nginx</code> or Apache default 404/"Welcome" page is a weaker and more ambiguous signal than it looks</strong> — it usually just means a reverse proxy is alive and correctly routing, but nothing is configured behind it for that hostname; on its own it does <em>not</em> confirm the backing resource is deletable/claimable by a third party. A provider-branded message (e.g. "No such app", "This site doesn't exist on &lt;Platform&gt;") is much stronger evidence, because it tells you specifically that the <em>platform itself</em> has no record of the resource — that's the signal worth chasing, not a generic server page.</p>
    <p>Test both <code>http://</code> and <code>https://</code> — behavior can differ, and the TLS certificate's subject/SANs can confirm or rule out whether the org still actively manages the host. Also map the full <code>CNAME</code> chain if there's more than one hop (<code>a.target.com → b.provider.com → c.provider.net</code>) before deciding where ownership/control actually ends.</p>

    <h4>4. Confirm claimability before reporting anything</h4>
    <p>Finding the provider is only step one. Check whether that specific provider's platform actually lets an unrelated third party register the exact resource name the DNS record points to — this varies enormously by provider and changes over time, so verify it for the actual service in front of you rather than assuming based on a reputation the provider may have fixed since.</p>
    <div class="tool-row"><span class="tname">can-i-take-over-xyz</span><span>The standard, actively-maintained reference for exactly this — a crowdsourced table of providers, whether they're currently vulnerable, the exact fingerprint string to look for, and how to confirm it for each one. Check the candidate's provider against this before doing anything else. <code>github.com/EdOverflow/can-i-take-over-xyz</code></span></div>

    <h4>5. Dangling DNS checklist</h4>
    <p>Work through this for every candidate before calling anything a takeover:</p>
    <div class="checklist">
      <ul>
        <li>Subdomain exists</li>
        <li>DNS record exists</li>
        <li>Record points externally</li>
        <li>External resource is missing</li>
        <li>Provider identified</li>
        <li>Provider's ownership model understood</li>
        <li>Resource is actually claimable</li>
        <li>Claimability independently verified</li>
        <li>No legitimate owner still controls it</li>
        <li>HTTPS behavior checked</li>
        <li>CNAME chain checked</li>
        <li>NS delegation checked where relevant</li>
      </ul>
    </div>
    <p>Also watch for <strong>wildcard DNS</strong> — if <code>random-string.target.com</code> resolves to something, check whether <code>*.target.com</code> is an intentional wildcard before treating an "unknown" subdomain as a takeover candidate; wildcards are a common source of false positives.</p>

    <h4>6. NS / subdomain delegation — a separate, bigger risk</h4>
    <p>CNAMEs aren't the only concern. If <code>dev.target.com</code> delegates its entire zone via <code>NS</code> to a third-party nameserver that's since been abandoned, and an attacker can register/control that delegated zone, the impact is substantially broader than a single web service — they control every record under that subdomain, not just one host. This needs more careful validation (check <code>NS</code>, <code>SOA</code>, DNSSEC, delegation status, nameserver ownership) than an ordinary CNAME case.</p>

    <h4>7. Record this for every candidate</h4>
    <div class="checklist single">
      <ul>
        <li>Subdomain / IP / DNS record type</li>
        <li>CNAME target / Final target (after following the full chain)</li>
        <li>Provider / Service</li>
        <li>HTTP response / HTTPS response / Status</li>
        <li>Provider-specific error text (exact string)</li>
        <li>Resource exists? Yes / No / Unknown</li>
        <li>Resource owned by the organization? Yes / No / Unknown</li>
        <li>Resource claimable? Yes / No / Unknown</li>
        <li>Historical DNS / CT certificate references</li>
        <li>OAuth / CORS / CSP references? Yes / No</li>
        <li>Cookie relationship</li>
        <li>Takeover confirmed? Yes / No / Unknown</li>
        <li>Impact</li>
      </ul>
    </div>
  `,
  treeHTML: `
    <div class="tree">
      <div class="tree-root">Subdomain found (recon / CT logs / DNS)</div>
      <div class="tree-q">Does the DNS record point to an internal or external service?</div>
      <div class="tree-branch">
        <div class="tree-opt"><span class="tree-node">Internal — not a takeover candidate (still worth a quick look for other issues)</span></div>
        <div class="tree-opt tree-yes">
          <span class="tree-tag">EXTERNAL</span><span class="tree-node">Identify the specific third-party provider</span>
          <div class="tree-sub">
            <div class="tree-q">Does the resource it points to still exist?</div>
            <div class="tree-branch">
              <div class="tree-opt tree-deny"><span class="tree-tag">YES, exists</span><span class="tree-node tree-pass">Probably not takeover — confirm it's genuinely the org's own active resource</span></div>
              <div class="tree-opt tree-allow">
                <span class="tree-tag">NO, dangling</span><span class="tree-node">Investigate further</span>
                <div class="tree-sub">
                  <div class="tree-q">Can that exact resource be claimed by anyone?</div>
                  <div class="tree-branch">
                    <div class="tree-opt tree-deny"><span class="tree-tag">NO</span><span class="tree-node">Misconfiguration, not proven exploitable — document but don't call it a confirmed takeover</span></div>
                    <div class="tree-opt tree-allow"><span class="tree-tag">YES</span><span class="tree-node tree-fail">Takeover candidate — confirm safely, within authorization, then assess what trusts this hostname (OAuth / CORS / CSP / cookies)</span></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
  burpHTML: `
    <ol>
      <li>Run your resolved candidate list through Burp (or just <code>httpx</code>) to batch-grab status codes and response bodies in one pass rather than curling each one by hand.</li>
      <li>For a promising candidate, send the request to Repeater and toggle between <code>HTTP</code> and <code>HTTPS</code> — behavior sometimes differs, and the TLS certificate's subject/SANs (visible in Burp's certificate viewer) can confirm or rule out whether the org still actively manages the host.</li>
      <li>Use Repeater to follow the full redirect/CNAME chain manually if the target hops through more than one hostname before landing on the final service — don't stop investigating at the first hop.</li>
      <li>If the hostname shows up anywhere in the main app's traffic (a CORS preflight response, a CSP header, an OAuth redirect parameter), capture that request specifically — it's your impact evidence, separate from the DNS/takeover evidence itself.</li>
    </ol>
  `,
  extraHTML: `
    <div class="tool-row"><span class="tname">nuclei</span><span>Ships community-maintained takeover-detection templates covering dozens of providers' exact fingerprint strings — the fastest way to sweep a large subdomain list. <code>subfinder -d target.com -silent | nuclei -t takeovers/ -o takeover-results.txt</code></span></div>
    <div class="tool-row"><span class="tname">Subjack</span><span>Purpose-built Go takeover scanner with a built-in fingerprint list. <code>subjack -w subs.txt -t 50 -timeout 30 -o results.txt -ssl</code></span></div>
    <div class="tool-row"><span class="tname">Subzy</span><span>Similar in spirit, cross-checks findings against the <code>can-i-take-over-xyz</code> fingerprint database directly. <code>subzy run --targets subs.txt --hide_fails</code></span></div>
    <p>Run at least two of the three against any large subdomain list — their fingerprint databases drift out of sync with each other as providers patch and un-patch over time, so a hit on one and a miss on the others is common and worth manually re-checking rather than trusting a single tool's verdict.</p>
    <p><strong>Treat every automated hit as a lead, not a finding.</strong> All three tools fingerprint off response text/status patterns, which produces real false positives (a provider changing their "not found" copy breaks old signatures in both directions). Manually walk through the decision tree above — provider identified, resource confirmed gone, resource confirmed claimable — before reporting anything a scanner flagged.</p>

    <h4 style="margin-top:22px;">One-page checklist — the full assessment worksheet</h4>
    <div class="checklist">
      <div class="checklist-group">
        <div class="checklist-group-title">Discovery</div>
        <ul>
          <li>Enumerate subdomains</li><li>CT logs</li><li>DNS</li><li>Historical DNS</li>
          <li>Search indexes</li><li>JS/assets</li><li>Source repositories</li><li>Mobile/API endpoints</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">DNS</div>
        <ul>
          <li>A</li><li>AAAA</li><li>CNAME</li><li>NS</li><li>CNAME chain</li><li>Wildcard</li><li>DNSSEC where relevant</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Service</div>
        <ul>
          <li>Identify provider</li><li>Identify service</li><li>Determine expected configuration</li>
          <li>Determine resource ownership</li><li>Check resource existence</li>
          <li>Check provider-specific error</li><li>Determine claimability</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Validation</div>
        <ul>
          <li>HTTP</li><li>HTTPS</li><li>TLS certificate</li><li>Redirects</li>
          <li>DNS resolution</li><li>Historical records</li><li>CT records</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Authorization / impact</div>
        <ul>
          <li>OAuth</li><li>CORS</li><li>CSP</li><li>Cookies</li><li>SSO</li><li>API trust</li>
          <li>Webhooks</li><li>Script/resource trust</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Reporting</div>
        <ul>
          <li>Hostname</li><li>DNS record</li><li>CNAME target</li><li>Provider</li>
          <li>Evidence resource is abandoned</li><li>Evidence resource is claimable</li>
          <li>Safe proof</li><li>Business impact</li><li>Remediation</li>
        </ul>
      </div>
    </div>
    <p>For remediation, recommend the organization removes stale DNS records when the associated service is decommissioned, and keeps an inventory mapping third-party resources to DNS names so service deletion and DNS cleanup happen together going forward.</p>
  `,
  reportYesHTML: `you've established the full chain — dangling external DNS record, specific provider identified, resource confirmed non-existent, and the exact resource confirmed claimable by an unrelated third party (per the provider's own documented behavior or <code>can-i-take-over-xyz</code>) — and ideally demonstrated control where your authorization explicitly covers that step.`,
  reportNoHTML: `the resource still resolves to the organization's own active content, the provider's "not found" response doesn't actually indicate a claimable resource (a generic nginx/Apache 404 alone, for instance), or you can't confirm claimability for that specific provider — "the CNAME is dangling" by itself is not a confirmed subdomain takeover.`
}

];
