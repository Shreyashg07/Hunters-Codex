/* ============================================================
   LOW HANGING FRUITS — PART 3
   Login-page specific injection and session classes.
   ============================================================ */

var LHF3 = [

/* ---------------- 1. IMPROPER OUTPUT NEUTRALIZATION ---------------- */
{
  id: "improper-output-neutralization",
  title: "Improper Output Neutralization on Login Parameters",
  category: "Injection (XSS / SQLi)",
  severity: "high",
  descriptionHTML: `
    <p>Login requests usually carry more than just <code>username</code> and <code>password</code> — hidden fields, CSRF tokens, a <code>form</code>/<code>action</code> identifier, "remember me" flags, and redirect/return-URL parameters all ride along in the same request. Those extra parameters are frequently tested far less than the credential fields themselves, and if any of them get reflected back into the HTML response (an error message, a pre-filled field, a redirect) without proper output encoding, that's a reflected XSS or injection point sitting right on the most sensitive page of the app.</p>
  `,
  impactHTML: `
    <p>Reflected XSS on a login page is particularly dangerous because it's the one page every user — including admins — visits while <em>not yet authenticated</em>, making it an effective phishing/credential-theft vector (inject a fake login form, or steal the real one's submission via JS). If the same unescaped parameter flows into a backend query instead of HTML, you may have SQL/NoSQL injection, which on a login endpoint can mean full authentication bypass.</p>
  `,
  severityHTML: `<p><strong>High → Critical.</strong> Confirmed reflected XSS on an unauthenticated login page is typically High; confirmed SQLi (especially if it leads to auth bypass or data extraction) is Critical.</p>`,
  stepsHTML: `
    <ol>
      <li>Capture a normal login POST in Burp Proxy and send it to Repeater.</li>
      <li>List <strong>every</strong> parameter in the raw body — not just <code>username</code>/<code>password</code>. Example shape:
        <pre><code>form=login&user=username&password=pass&redirect=/dashboard&csrf=abc123</code></pre>
      </li>
      <li>One at a time, replace each non-credential parameter's value with an encoded test payload and resend:
        <pre><code># XSS probes
"&gt;&lt;script&gt;alert(1)&lt;/script&gt;
'&gt;&lt;img src=x onerror=alert(1)&gt;

# SQLi probes
' OR '1'='1
' OR SLEEP(5)-- -
admin'-- -

# open-redirect-adjacent (on redirect/return/next params)
https://evil.com
//evil.com
/\\evil.com</code></pre>
      </li>
      <li>For XSS: check whether the payload is reflected unescaped anywhere in the HTML response (view source, don't trust the rendered page alone — some payloads execute silently).</li>
      <li>For SQLi: watch for a changed error message, a noticeably delayed response on the <code>SLEEP()</code> payload (time-based blind), or a successful login/bypass on the boolean payload.</li>
      <li>Try both raw and URL/double-URL-encoded variants — some login handlers decode the body before validation, so an already-encoded payload can slip past a naive filter that only checks the raw string.</li>
    </ol>
  `,
  extraHTML: `
    <p>Keep going past the obvious fields — test these too, since they're commonly overlooked on exactly this page:</p>
    <ul>
      <li><code>remember_me</code> / <code>stay_logged_in</code> flags — type-confusion payloads (array instead of boolean, SQLi inside what's expected to be a boolean).</li>
      <li>Any <code>lang</code>/<code>locale</code> parameter the login page reads — these are frequently used to pull a translation string file and can be vulnerable to path traversal or local file inclusion, not just XSS.</li>
      <li>The <code>Referer</code> and <code>User-Agent</code> headers themselves, if the app logs failed login attempts somewhere an admin later views them (second-order/stored XSS via a security log viewer).</li>
      <li>Error messages that differ for "user not found" vs. "wrong password" — a username-enumeration issue, worth noting alongside any injection finding on the same page.</li>
    </ul>
    <p><strong>Also test CRLF injection:</strong> if any login parameter reflects into a response header (a redirect <code>Location</code>, a <code>Set-Cookie</code>), try <code>%0d%0aSet-Cookie:%20injected=1</code> — successful header injection can enable response splitting or session-fixation-style attacks layered on top of the same parameter.</p>
  `,
  reportYesHTML: `a payload in any login-adjacent parameter executes as JavaScript in the response, or produces clear evidence of a backend query being altered (time delay, error change, or an actual bypass) — capture the raw request/response as PoC.`,
  reportNoHTML: `all values are properly HTML-encoded on output and parameterized on the query side — a payload that's visible in the response but correctly escaped (shown as literal text, not executed) is not a bug.`
},

/* ---------------- 2. FORMAT STRING / SSTI ---------------- */
{
  id: "external-format-string",
  title: "Externally-Controlled Format String",
  category: "Injection (Format String / SSTI)",
  severity: "medium",
  descriptionHTML: `
    <p>A classic format-string bug (CWE-134) happens when user input is passed directly as the <em>format</em> argument to a C-family function like <code>printf(user_input)</code> instead of <code>printf("%s", user_input)</code> — letting an attacker use format specifiers (<code>%x</code>, <code>%s</code>, <code>%n</code>) to read stack memory or crash the process. This exact pattern is rare in modern web stacks (most languages don't expose it), but it still turns up in native components, legacy CGI, embedded device panels, and C-based logging libraries wrapped by a web frontend.</p>
    <p>Its far more common modern cousin is <strong>Server-Side Template Injection (SSTI)</strong> — where user input is concatenated into a template <em>string</em> that a template engine (Jinja2, Freemarker, Velocity, Twig, Smarty, Thymeleaf) then evaluates, rather than being passed in as a safe, literal value. Conceptually it's the same root cause — user input controlling something that gets interpreted rather than displayed — and it's a much higher-value finding, since SSTI frequently escalates to full remote code execution.</p>
  `,
  impactHTML: `
    <p>Classic format string: information disclosure (leaked memory/stack contents) up to a crash/DoS, occasionally memory corruption in native code. SSTI: ranges from information disclosure up to <strong>full RCE</strong> depending on the engine and how tightly the execution environment is sandboxed.</p>
  `,
  severityHTML: `<p>Classic format string: <strong>Medium</strong> typically (info leak/crash), rarely seen in pure web stacks. SSTI: starts at <strong>Medium</strong> for confirmed template evaluation, escalates to <strong>Critical</strong> the moment you can prove code execution.</p>`,
  stepsHTML: `
    <h4 style="margin-top:0">Where to test</h4>
    <p>Any field that might feed into a message template rather than being stored/shown as a plain literal: password-reset "hint" fields, custom notification/alert message builders, email subject-line templates, "about me"/bio fields if they go through a rendering pipeline, export filename patterns, report-generation inputs, and any admin-configurable "message template" feature.</p>

    <h4>Classic format-string probe</h4>
    <pre><code>%x%x%x%x%x
%s%s%s%s%s
%n</code></pre>
    <p>Valid sign: an application error referencing a formatting function, a crash, or garbage-looking memory content reflected back. Treat a clean, unaffected response as the expected (safe) outcome on virtually all modern web backends.</p>

    <h4>SSTI probe — try across engines, since syntax differs</h4>
    <pre><code>{{7*7}}        # Jinja2, Twig, Nunjucks
\${7*7}         # Freemarker, Thymeleaf, JSP EL
#{7*7}         # Ruby ERB / some Java EL contexts
&lt;%= 7*7 %&gt;      # ERB
*{7*7}         # Thymeleaf selection expressions</code></pre>
    <p>Confirmation is simple and unambiguous: if the rendered output shows <strong>49</strong> instead of the literal payload text, the server evaluated your input as code — that's SSTI, full stop. From there, identify the exact engine (each has a distinct syntax fingerprint) before attempting any further escalation.</p>
  `,
  extraHTML: `
    <div class="tool-row"><span class="tname">tplmap</span><span>Automates SSTI detection and exploitation across engines, similar in spirit to sqlmap. <code>python2 tplmap.py -u 'https://target.com/page?name=John'</code></span></div>
    <div class="tool-row"><span class="tname">Burp Suite</span><span>Manual probing via Repeater/Intruder with a small SSTI payload list is usually enough to confirm the engine before reaching for automation.</span></div>
    <p>Always confirm with the simplest arithmetic payload first (<code>{{7*7}}</code>) before attempting known RCE gadgets for that specific engine — jumping straight to an RCE payload against an unconfirmed engine just produces noise and false negatives.</p>
    <p>PortSwigger's SSTI methodology (detect → identify the engine → construct an exploit) is the standard reference for taking a confirmed <code>{{7*7}}</code> hit further — worth reading before attempting engine-specific RCE payloads.</p>
  `,
  reportYesHTML: `a format-specifier or template-syntax payload is evaluated (arithmetic resolves, memory/garbage is reflected, or the process errors/crashes in a way tied directly to your input) — identify and state the specific engine/function involved.`,
  reportNoHTML: `all payload variants are reflected back as inert literal text, or produce a generic, unrelated error — this class has a low hit rate on modern stacks, so a handful of clean negatives across the common syntaxes is expected and not worth over-testing.`
},

/* ---------------- 3. INFO DISCLOSURE VIA STACK TRACES & VERSION ---------------- */
{
  id: "stack-trace-version-disclosure",
  title: "Information Disclosure via Stack Traces & Version Banners",
  category: "Security Misconfiguration / Information Disclosure",
  severity: "low",
  descriptionHTML: `
    <p>Two related leaks that both come from debug/verbose behavior left on in production: (1) unhandled exceptions rendering a full stack trace to the end user instead of a generic error page — revealing file paths, framework internals, query structure, and sometimes fragments of source; and (2) explicit version banners — server headers, CMS generator tags, admin-panel footers, JS library comments — revealing the exact software version in use.</p>
  `,
  impactHTML: `
    <p>A stack trace alone mostly hands an attacker a map of your internals (file structure, ORM/framework in use, sometimes DB table/column names from a SQL error). A disclosed version number becomes genuinely dangerous the moment it matches a <strong>known, publicly-documented CVE</strong> — at that point the severity of the <em>finding</em> should reflect the severity of whatever that CVE actually enables, not just "I found a version string."</p>
  `,
  severityHTML: `<p><strong>Low → Medium</strong> for the disclosure itself. Re-rated to match the underlying CVE's severity (often High/Critical) once you can show the disclosed version has a known public exploit — that's the chain that actually makes this worth a strong report.</p>`,
  stepsHTML: `
    <h4 style="margin-top:0">Triggering stack traces — malformed-input cheat sheet</h4>
    <div class="dork-list">
      <code>admin'--</code>
      <code>' OR 1=1 --</code>
      <code>{{invalid_template_syntax</code>
      <code>null byte: value%00</code>
      <code>extremely long string (10k+ chars) in a numeric field</code>
      <code>wrong Content-Type (send form data as raw JSON, or vice versa)</code>
      <code>malformed JSON body: { "key": }</code>
      <code>negative numbers / floats in an integer-only field (id=-1, id=1.5)</code>
      <code>unexpected array/object where a scalar is expected: user[]=1&amp;user[]=2</code>
    </div>
    <p>Run these against login, search, and any form with structured input — then check whether the response is a clean generic error or a full stack trace with file paths and line numbers.</p>

    <h4>Finding version info</h4>
    <ul>
      <li>HTTP response headers on every request: <code>Server:</code>, <code>X-Powered-By:</code>, <code>X-AspNet-Version:</code>, <code>X-Generator:</code>.</li>
      <li>404/error pages — a framework's own debug 404 page (Django/Rails/Laravel/Express default error pages) often states the exact framework version.</li>
      <li>Page source comments, JS library headers (<code>/* jQuery v1.8.3 */</code>-style), CMS meta generator tags.</li>
      <li>Static asset query strings used for cache-busting (<code>app.js?v=2.4.1</code>) often mirror the actual app/library version.</li>
      <li>Exposed <code>/package.json</code>, <code>/composer.lock</code>, <code>/.git/</code> (ties directly into the Directory Listing entry) if a listing or direct path leak exposes them.</li>
    </ul>

    <h4>Tools for version fingerprinting</h4>
    <div class="tool-row"><span class="tname">whatweb</span><span><code>whatweb -a 3 target.com</code> — aggressive fingerprinting of CMS/framework/library versions.</span></div>
    <div class="tool-row"><span class="tname">Wappalyzer</span><span>Browser extension, fast passive fingerprint of the whole stack while you browse normally.</span></div>
    <div class="tool-row"><span class="tname">wafw00f</span><span><code>wafw00f target.com</code> — identifies the WAF in front of the target, useful context alongside version info.</span></div>

    <h4>Once you have a version: check for CVEs</h4>
    <p>Search <code>"&lt;software&gt; &lt;exact version&gt;" CVE</code>, then confirm on <code>nvd.nist.gov</code> and <code>exploit-db.com</code>. If the exact disclosed version matches a CVE with a public PoC, that's the detail that turns a routine Low-severity disclosure into a report worth real attention — lead with it.</p>
  `,
  extraHTML: `
    <p><strong>Also check for exposed source maps:</strong> request <code>/main.js.map</code> (or whatever your bundled JS file is named + <code>.map</code>) — an exposed source map hands over de-minified original source, often including comments, internal API paths, and occasionally hardcoded values never meant to ship.</p>
  `,
  reportYesHTML: `a raw stack trace with file paths/internals reaches the end user, or a precisely-versioned, outdated component is disclosed and you can point to a matching public CVE — the CVE link is what makes this worth prioritizing.`,
  reportNoHTML: `errors are generic/handled gracefully, or a version is disclosed but is current/fully patched with no known matching CVE — most programs treat bare "I found your software version" with no further chain as Informational.`
},

/* ---------------- 4. SESSION FIXATION ---------------- */
{
  id: "session-fixation",
  title: "Session Fixation",
  category: "Broken Authentication / Session Management",
  severity: "high",
  descriptionHTML: `
    <p>Session fixation (CWE-384) is about whether the server issues a <strong>brand-new</strong> session identifier at the moment a user authenticates, or whether it keeps reusing whatever session ID was already assigned <em>before</em> login. If the pre-login ID survives unchanged across authentication, anyone who already knows that ID — because they set it themselves, or planted it on the victim via a crafted link — automatically becomes authenticated as the victim the instant the victim logs in, without ever needing their password.</p>
    <p class="callout sev-info" style="display:block;border:1px solid rgba(157,123,255,0.35);background:var(--violet-dim,rgba(157,123,255,0.1));border-radius:8px;padding:14px 18px;">A quick correction on the test described in most informal checklists (swapping cookies between two <em>already-logged-in</em> accounts, A and B): that's testing something closer to session-cookie confusion between two separate authenticated sessions, not fixation. True fixation specifically hinges on the session ID being fixed <strong>before</strong> authentication and surviving the login event unchanged — the test below targets that directly.</p>
  `,
  impactHTML: `
    <p>Full account takeover with zero credential theft required — the attacker never needs the victim's password, only the ability to get them to use a known session ID once, then simply waits for them to log in normally.</p>
  `,
  severityHTML: `<p><strong>High.</strong> This is a direct, low-complexity path to account takeover whenever it's present.</p>`,
  stepsHTML: `
    <h4 style="margin-top:0">The direct test (no second browser needed)</h4>
    <ol>
      <li>Open the login page in a fresh, unauthenticated session. In Burp Proxy (or DevTools → Application → Cookies), note the session cookie's value <em>before</em> logging in — call it <code>SID_PRE</code>.</li>
      <li>Submit valid login credentials and let the request complete.</li>
      <li>Check the <code>Set-Cookie</code> header on the login response (or the cookie's value immediately after login) — call it <code>SID_POST</code>.</li>
      <li><strong>If <code>SID_PRE</code> and <code>SID_POST</code> are the same value</strong>, the server never rotated the session ID at the authentication boundary — that alone is the vulnerability.</li>
    </ol>

    <h4>Proving real-world impact (two-browser PoC)</h4>
    <ol>
      <li>In Browser A (the "attacker," not logged in), load the login page and capture <code>SID_PRE</code> as above — don't log in.</li>
      <li>Get that same <code>SID_PRE</code> value adopted by Browser B (the "victim") <em>before</em> they authenticate — in a lab test, set it directly as Browser B's cookie; in the wild this is typically done via a URL-based session parameter (some older Java/PHP apps accept <code>;jsessionid=...</code> or <code>?PHPSESSID=...</code> in the URL) or a cookie planted from a sibling subdomain.</li>
      <li>In Browser B, log in normally with valid credentials while holding that fixed <code>SID_PRE</code> cookie.</li>
      <li>Go back to Browser A — which never logged in — and refresh an authenticated page using the same, unchanged session ID.</li>
      <li><strong>Valid bug:</strong> Browser A is now authenticated as the Browser B user, with no credentials ever entered. <strong>Not a bug:</strong> Browser A's session was already invalid/different, because the server correctly issued a fresh session ID the moment Browser B authenticated.</li>
    </ol>
  `,
  extraHTML: `
    <p>Also specifically check whether the app accepts a session identifier <strong>supplied via the URL</strong> at all (<code>;jsessionid=</code>, <code>?sessid=</code>) rather than only via cookie — URL-based session tokens are the classic real-world fixation delivery mechanism, since a link is all it takes to plant one on a victim, and they also leak via <code>Referer</code> headers and browser history far more readily than cookies do.</p>
    <p><strong>Also check cookie scope:</strong> if the session cookie is set with a broad <code>Domain=.target.com</code> rather than scoped to the exact host, a less-trusted subdomain (an old blog, a staging box) can plant a cookie the main app will accept — a realistic, concrete way the "attacker plants a known session ID on the victim" step actually happens in the wild, beyond the URL-parameter method above.</p>
  `,
  reportYesHTML: `the session identifier present before login is still valid and unchanged after a successful authentication — <code>SID_PRE === SID_POST</code> is the whole bug; the two-browser walkthrough is just the impact demonstration.`,
  reportNoHTML: `the server issues a new session ID on every successful login (the pre-auth cookie becomes invalid the moment authentication succeeds) — correct, secure behavior, even if the app also happens to accept URL-based session parameters elsewhere.`
}

];
