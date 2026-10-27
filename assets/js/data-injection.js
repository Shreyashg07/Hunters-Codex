/* ============================================================
   INJECTION
   HTTP Host Header Injection — when different components trust
   different hostname values, or an untrusted hostname reaches a
   security-sensitive operation. Full H01–H14 methodology.
   ============================================================ */

var INJECTION = [

/* ---------------- 1. HTTP HOST HEADER INJECTION ---------------- */
{
  id: "host-header-injection",
  title: "HTTP Host Header Injection",
  category: "Injection (Host Header)",
  severity: "high",
  descriptionHTML: `
    <p>The HTTP <code>Host</code> header tells an HTTP/1.1 server which hostname the client intends to reach. Reverse proxies, load balancers, and application frameworks often use it to route requests or construct absolute URLs (redirects, password-reset links, canonical tags, cache keys). A vulnerability exists when different application components trust different hostname values, or when an untrusted hostname is used for a security-sensitive operation.</p>
    <p>The question every test on this page answers: <strong>can you influence a security-sensitive server-side decision by changing the hostname-related input, while keeping the request directed at the authorized target?</strong></p>
  `,
  impactHTML: `
    <p>Impact spans a huge range depending on which component trusts the value and what it's used for:</p>
    <ul>
      <li><strong>Password-reset poisoning:</strong> a recovery email is built with an attacker-controlled hostname — direct path to account takeover.</li>
      <li><strong>Authorization bypass:</strong> a protected route trusts the hostname to decide "internal" vs. "external" caller — <code>403</code> becomes <code>200</code>.</li>
      <li><strong>Web cache poisoning:</strong> a manipulated, cacheable response gets served to other users from a shared cache.</li>
      <li><strong>Open-redirect-adjacent:</strong> login/logout/invitation flows build a <code>Location</code> header from the hostname.</li>
      <li><strong>Cosmetic only:</strong> a canonical link or Open Graph URL reflects the hostname with no further consequence — informational.</li>
    </ul>
  `,
  severityHTML: `
    <p><strong>Informational → Low</strong> for reflection that never reaches a sensitive operation. Climbs to <strong>High → Critical</strong> the moment it reaches a password-reset link, an authorization decision, or a shared cache — those three are the "bug bounty gold" categories on this page. Score the proven consequence, not the header manipulation itself.</p>
  `,
  stepsHTML: `
    <h4 style="margin-top:0">Before you start: keep the destination fixed</h4>
    <p>The <code>Host</code> header and the network destination are two different things. Changing the hostname in your browser's address bar just connects you to a different server — that's not the test. In Burp Repeater, keep the request pointed at the authorized target and edit only the header field itself. For HTTPS, <strong>TLS SNI and certificate validation happen separately from the HTTP Host header</strong> and can affect whether the request reaches the application at all — a failed request may just be an SNI mismatch, not a successful validation check.</p>
    <p>Capture a baseline first: normal status code, response body, redirect location, cache headers, and any hostname-dependent URLs. Keep the original request so every experiment has something to diff against.</p>

    <div class="checklist">
      <div class="checklist-title">☐ The complete test matrix (H01–H14)</div>
      <div class="checklist-group">
        <div class="checklist-group-title">Core header tests</div>
        <ul>
          <li>H01 Arbitrary Host — are unrecognized hostnames accepted?</li>
          <li>H02 Host reflection — does the response echo the supplied hostname?</li>
          <li>H03 Forwarded-host headers — do proxy headers override Host?</li>
          <li>H04 Port parsing — do validation and port parsing disagree?</li>
          <li>H05 Domain suffix validation — is hostname matching too permissive?</li>
          <li>H06 Duplicate Host — do components disagree on which value wins?</li>
          <li>H07 Absolute-form request target — do URL and Host disagree?</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Impact-bearing tests</div>
        <ul>
          <li>H08 Host-dependent redirects — does it reach <code>Location</code>?</li>
          <li>H09 Password reset URLs — does recovery trust the hostname?</li>
          <li>H10 Cache behavior — is manipulated content cached and shared?</li>
          <li>H11 Authorization decisions — does it affect protected-route access?</li>
          <li>H12 Virtual host routing — unintended vhost reached?</li>
          <li>H13 TLS/proxy consistency — do edge and backend disagree?</li>
          <li>H14 Secondary inputs — does the value reach another sensitive op?</li>
        </ul>
      </div>
    </div>

    <h4>H01 — Arbitrary Host header</h4>
    <pre><code>GET / HTTP/1.1
Host: target.example
Connection: close</code></pre>
    <p>Change only the Host value to a hostname you control (or a reserved test domain) and resend:</p>
    <pre><code>GET / HTTP/1.1
Host: marker.example
Connection: close</code></pre>
    <p>Compare status code, body, response headers, redirects — repeat across a few relevant endpoints (homepage, login, account recovery).</p>
    <ul>
      <li><code>400</code>/<code>421</code> — likely rejected by host validation.</li>
      <li><code>301</code>/<code>302</code> — inspect <code>Location</code> for hostname influence.</li>
      <li><code>200</code> — accepted, but alone proves nothing yet.</li>
      <li>Response contains <code>marker.example</code> — investigate whether it reaches a sensitive URL/operation.</li>
    </ul>
    <p>A CDN/proxy rejecting unexpected hosts before the app ever sees the request is normal, expected behavior — not a bug.</p>

    <h4>H02 — Host reflection</h4>
    <p>Inspect the raw response — HTML body, headers, redirect target — for everywhere the supplied hostname appears:</p>
    <div class="checklist single">
      <ul>
        <li>Absolute URLs in HTML</li>
        <li>Script/stylesheet URLs</li>
        <li>Canonical links</li>
        <li>Open Graph URLs</li>
        <li>JSON fields containing a domain</li>
        <li>Email/notification preview links</li>
        <li>Redirect destinations</li>
        <li>URLs generated by recovery/invitation workflows</li>
      </ul>
    </div>
    <p>Reflection alone — <code>&lt;link rel="canonical" href="https://marker.example/account"&gt;</code> — is not impact. Determine whether the affected URL is purely cosmetic or can influence script loading, reset links, shared cache entries, or another sensitive operation.</p>

    <h4>H03 — Forwarded-host header family</h4>
    <p>Test each header individually, one change per request, keeping the normal Host value present:</p>
    <pre><code>Host: target.example
X-Forwarded-Host: marker.example</code></pre>
    <p>Then reset and test these separately — never stack them:</p>
    <div class="dork-list">
      <code>X-Host: marker.example</code>
      <code>X-Forwarded-Server: marker.example</code>
      <code>X-HTTP-Host-Override: marker.example</code>
      <code>Forwarded: host=marker.example</code>
    </div>
    <p>For each: does the response contain the marker? Does the redirect target change? Does it generate absolute URLs with it? Is it endpoint-specific? Is it stripped or overwritten by the frontend proxy? Don't assume every framework processes these headers the same way.</p>

    <h4>H08 — Redirects &amp; absolute URL generation</h4>
    <p>Particularly useful on login, logout, invitation, and recovery flows:</p>
    <ol>
      <li>Capture a normal request that produces a redirect, record the baseline <code>Location</code>.</li>
      <li>Repeat with a controlled alternate Host value.</li>
      <li>Compare whether the redirect's scheme, hostname, or path changes.</li>
      <li>Check whether the destination is validated against an allowlist at all.</li>
    </ol>
    <p>Host manipulation that merely changes a canonical URL may be informational — it's a meaningful finding only once the untrusted value causes a genuinely security-relevant redirect.</p>

    <h4>H09 — Password reset poisoning (the highest-value test on this page)</h4>
    <ol>
      <li>Use a test account you own — never someone else's.</li>
      <li>Capture the normal password-reset request in Burp.</li>
      <li>Submit it with the ordinary Host header and confirm the baseline recovery link via your own test mailbox.</li>
      <li>Repeat with a controlled hostname-related input (Host, or one of the H03 forwarded-host variants).</li>
      <li>Inspect the resulting email — did the link's hostname change?</li>
      <li>Confirm the token still binds to the intended account and expires normally.</li>
    </ol>
    <p><strong>Never send manipulated reset emails to other people or attempt to collect other users' tokens</strong> — this only works safely against your own account. Real finding: the server builds a recovery link from an untrusted hostname, reproducibly.</p>

    <h4>H10 — Web cache poisoning</h4>
    <p>Compare original vs. modified-Host requests while watching <code>Cache-Control</code>, <code>Age</code>, <code>Vary</code>, <code>Via</code>, <code>ETag</code>, and any CDN-specific cache-status headers. A cache-buster query parameter helps tell fresh responses apart from cached ones. The real question: is the hostname reflected into a <em>cacheable</em> response, and is that input actually part of the cache key? <strong>Don't poison a shared production cache to prove impact</strong> — use a program-provided lab or isolated cache if one's offered.</p>

    <h4>H11 — Host-based authorization bypass</h4>
    <ol>
      <li>Capture a normal request to a protected endpoint with your ordinary test account (expect <code>403</code>).</li>
      <li>Change only the hostname-related input.</li>
      <li>Compare — does <code>403</code> become <code>200</code>? Verify the response actually contains the protected resource, not just a different error page or virtual host.</li>
      <li>Stop once you've established safe, reproducible proof. Don't perform administrative changes or delete records to demonstrate impact further.</li>
    </ol>

    <h4>H04–H07, H12–H13 — quick reference</h4>
    <div class="checklist">
      <ul>
        <li><strong>H04 Port parsing</strong> — compare <code>Host: target.example:443</code> vs. <code>Host: target.example:invalid</code>; does malformed syntax get normalized, rejected, or passed raw to another component?</li>
        <li><strong>H05 Domain suffix validation</strong> — test <code>target.example.marker.example</code>, <code>not-target.example</code>, <code>targetexample</code> against the intended domain; look for a string-suffix check instead of a real label-boundary check.</li>
        <li><strong>H06 Duplicate Host</strong> (lab only) — send two <code>Host</code> headers in one request; does the server use the first value, the last, or reject it outright?</li>
        <li><strong>H07 Absolute-form request target</strong> — <code>GET https://target.example/ HTTP/1.1</code> with a different <code>Host</code> header; compare routing and generated URLs against the ordinary relative-path request.</li>
        <li><strong>H12 Virtual host routing</strong> — does changing Host return a different application, a default vhost page, or an unexpected login page? Only test hostnames explicitly in scope.</li>
        <li><strong>H13 TLS/proxy consistency</strong> — compare which layer (CDN, proxy, or app) actually produced the response using available headers/error signatures; a rejected request may just be SNI, not host validation.</li>
      </ul>
    </div>

    <h4>Validation bypass patterns — quick reference</h4>
    <div class="checklist single">
      <ul>
        <li><code>Host: marker.example</code> — unexpected hostname, establishes whether arbitrary hosts are accepted</li>
        <li><code>Host: target.example:443</code> — valid hostname with explicit port, compares normalization</li>
        <li><code>Host: target.example:invalid</code> — invalid port syntax, checks for inconsistent validation</li>
        <li><code>Host: not-target.example</code> — deceptive suffix, checks domain-boundary validation</li>
        <li><code>Host: sub.target.example</code> — legitimate subdomain, confirms intended subdomain policy</li>
        <li><code>X-Forwarded-Host: marker.example</code> — forwarded-host override, checks proxy header trust</li>
        <li>Two <code>Host</code> headers — duplicate Host, checks parser disagreement (lab only)</li>
        <li>Absolute URL + Host header — absolute-form request, compares target vs. header interpretation</li>
      </ul>
    </div>

    <h4>H14 — Host-dependent secondary inputs</h4>
    <p>The Host header isn't a normal parameter, but applications may copy its value into other inputs entirely. Check each separately:</p>
    <div class="checklist">
      <ul>
        <li>Query parameters — does a URL param override the hostname used in redirects/callbacks?</li>
        <li>JSON request body — is a supplied URL/domain trusted for a sensitive action?</li>
        <li>Form submissions — do invitation/recovery/verification URLs use request-derived host data?</li>
        <li>Cookies — is hostname-dependent state incorrectly trusted?</li>
        <li>API headers — do proxy-specific hostname headers affect generated links?</li>
        <li>Response headers — do <code>Location</code>/<code>Content-Location</code>/link headers use an untrusted hostname?</li>
      </ul>
      <p style="margin:8px 0 0;font-size:0.82rem;color:var(--ink-faint);">Treat these as secondary paths — a user-controlled URL field or cookie issue may actually be a separate vulnerability class. Report the real root cause rather than labeling everything "Host header injection."</p>
    </div>
  `,
  treeHTML: `
    <div class="tree">
      <div class="tree-root">Host-related input accepted somewhere (Host, X-Forwarded-Host, X-Host, Forwarded, absolute-form target, HTTP/2 :authority…)</div>
      <div class="tree-q">Does changing it produce any observable difference?</div>
      <div class="tree-branch">
        <div class="tree-opt tree-no"><span class="tree-tag">NO</span><span class="tree-node">Try the other header variants (the H03 family) before concluding nothing trusts it</span></div>
        <div class="tree-opt tree-yes">
          <span class="tree-tag">YES</span><span class="tree-node">Identify which component trusts it — CDN/proxy, backend app, or a specific feature</span>
          <div class="tree-sub">
            <div class="tree-q">Does it reach a security-sensitive operation (reset link, redirect target, cache key, auth decision, internal routing)?</div>
            <div class="tree-branch">
              <div class="tree-opt tree-deny"><span class="tree-tag">NO</span><span class="tree-node tree-pass">Cosmetic only (e.g. a canonical tag) — informational at most, don't overclaim</span></div>
              <div class="tree-opt tree-allow">
                <span class="tree-tag">YES</span><span class="tree-node">Can you safely reproduce a concrete, provable consequence?</span>
                <div class="tree-sub">
                  <div class="tree-q">Reset email contains the attacker domain? 403→200 on a protected route? Poisoned response served to a second, clean request?</div>
                  <div class="tree-branch">
                    <div class="tree-opt tree-deny"><span class="tree-tag">NOT YET</span><span class="tree-node">Needs more investigation — don't report yet</span></div>
                    <div class="tree-opt tree-allow"><span class="tree-tag">YES</span><span class="tree-node tree-fail">Reportable — document which component trusts it, what changed, and the proven impact</span></div>
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
      <li><strong>Keep the destination fixed.</strong> Changing the hostname in your browser's address bar just connects you to a different server — that's not the test. In Repeater, keep the request pointed at the authorized target and edit only the Host (or forwarded-host) field.</li>
      <li>Capture a baseline in Proxy → HTTP history, send to Repeater, and record the normal status, body, redirect location, cache headers, and hostname-dependent URLs before changing anything.</li>
      <li>Edit one header at a time — never stack multiple Host-related changes in the same request, or you won't know which one caused a behavior change.</li>
      <li>For a focused sweep: send the baseline to <strong>Intruder</strong>, mark only the hostname value as the payload position, load a small list of controlled test values, keep a low request rate, and compare status code, response length, redirect destination, and content across results.</li>
      <li>Don't infer a vulnerability from response length alone — different virtual hosts and CDN error pages can differ in size with zero security impact.</li>
      <li>Send anything interesting back to Repeater for manual validation before drawing conclusions.</li>
    </ol>
  `,
  extraHTML: `
    <div class="tool-row"><span class="tname">Param Miner (Burp extension)</span><span>The standard tool for this exact class — automatically probes for unkeyed/hidden headers and parameters that influence the response, including Host-header-style inputs, and flags web-cache-poisoning-relevant findings. Install via the BApp Store, then right-click a request → "Guess headers" / "Guess param names".</span></div>
    <div class="tool-row"><span class="tname">httpx</span><span>Useful for bulk-probing a list of endpoints with a modified Host header once you've confirmed one vulnerable pattern manually. <code>httpx -l urls.txt -H "Host: marker.example" -sc -cl -title</code></span></div>
    <p><strong>Don't forget HTTP/2:</strong> if the target negotiates HTTP/2, there's no literal <code>Host</code> header — the equivalent is the <code>:authority</code> pseudo-header. Burp Repeater lets you edit this directly in HTTP/2 mode; run the same H01–H03 patterns against <code>:authority</code> specifically, since some backends handle HTTP/1.1 Host validation carefully but miss the HTTP/2 equivalent entirely.</p>
    <p>Recommended hands-on labs before trying the higher-risk categories (cache poisoning, auth bypass) live: PortSwigger's Host header learning path, its dedicated Host-header authentication-bypass lab, and its ambiguous-request cache-poisoning lab — practicing exploitation in a deliberately vulnerable environment first is the right call before touching a live program's cache or auth logic with these techniques.</p>
  `,
  reportYesHTML: `a manipulated hostname reproducibly changes a sensitive operation — a recovery link, protected-resource access, or a poisoned cached response actually served to a second, clean request — and you can safely demonstrate the consequence. Name exactly which component trusts the value and what concrete impact you proved.`,
  reportNoHTML: `a malformed header just returns an error, a hostname is reflected without reaching any sensitive operation, or a redirect/cache/routing difference exists but you can't yet prove a concrete security consequence — that's "needs more investigation," not a finding yet. A CDN rejecting unexpected hosts outright is the system working correctly.`
}

];