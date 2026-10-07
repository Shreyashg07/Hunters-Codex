/* ============================================================
   BROKEN ACCESS CONTROL
   CSRF and IDOR/BOLA — the two classes where the server trusts
   the client's claim about who's asking, or what they're asking
   for, instead of actually checking.
   ============================================================ */

var ACCESS_CONTROL = [

/* ---------------- 1. CSRF ---------------- */
{
  id: "csrf",
  title: "Cross-Site Request Forgery (CSRF)",
  category: "Broken Access Control",
  severity: "high",
  descriptionHTML: `
    <p>Browsers automatically attach cookies to every request sent to a domain, regardless of which site actually triggered that request. CSRF abuses this: an attacker hosts a page anywhere on the internet that silently submits a request to the target application. If the victim is logged into the target in the same browser, their session cookie rides along, and the server has no way to tell the request apart from one the victim meant to send themselves.</p>
    <p>The defense is proving the request actually originated from the application's own pages — a per-session (or per-action) token the attacker's page can't know or predict, validated server-side on every state-changing request.</p>
  `,
  impactHTML: `
    <p>Impact tracks whatever the forged request does — this is the single most important thing to get right when triaging a CSRF finding. Prioritize requests that change server-side state and don't require re-entering a password or a second confirmation step:</p>
    <ul>
      <li><strong>Account takeover setup:</strong> change email, change password, add a second email, disable 2FA, add a trusted device.</li>
      <li><strong>Financial:</strong> transfer funds, add a payment method, change a payout/withdrawal address.</li>
      <li><strong>Privilege/state:</strong> change a role, grant a permission, create an API key, add a user to an organization.</li>
      <li><strong>Data:</strong> delete a resource, modify an order, change an address, post a message as the victim.</li>
    </ul>
  `,
  severityHTML: `
    <p>Ranges from <strong>Critical</strong> (forging an email/password change, which is a direct path to full account takeover) down to <strong>Low</strong> (forging a cosmetic preference toggle). The CSRF flaw itself is constant — what you're actually scoring is the forged action, so always name the specific state change in the report rather than just "CSRF found."</p>
  `,
  stepsHTML: `
    <h4 style="margin-top:0">1. Find the attack surface</h4>
    <p>Grep captured traffic for state-changing parameters: <code>email</code>, <code>password</code>, <code>new_password</code>, <code>username</code>, <code>role</code>, <code>is_admin</code>, <code>amount</code>, <code>account</code>, <code>user_id</code>, <code>recipient</code>, <code>redirect</code>, <code>delete</code>, <code>action</code> — and feature-specific routes like <code>?action=change-email</code> or <code>?action=transfer</code>. Walk every "change X" / "add X" / "delete X" flow in the app, especially ones that don't ask for your password again.</p>

    <h4>2. Baseline the request</h4>
    <pre><code>POST /myaccount/changeemail HTTP/1.1
Host: target.example
Cookie: session=...
Content-Type: application/x-www-form-urlencoded

email=test@example.com&csrf=VALID_TOKEN</code></pre>
    <p>Confirm it succeeds normally first. Then start removing things.</p>

    <h4>3. Build a cross-site PoC</h4>
    <p>A minimal auto-submitting form, hosted on any domain you control (or just saved as a local <code>.html</code> file and opened in the same browser where you're logged into the target):</p>
    <pre><code>&lt;html&gt;
  &lt;body onload="document.forms[0].submit()"&gt;
    &lt;form action="https://target.example/myaccount/changeemail" method="POST"&gt;
      &lt;input type="hidden" name="email" value="attacker@evil.com"&gt;
    &lt;/form&gt;
  &lt;/body&gt;
&lt;/html&gt;</code></pre>
    <p>Open it while logged into the target in the same browser. If the email actually changes, you have a working PoC.</p>

    <h4>4. Work through the token checklist</h4>
    <ul>
      <li><strong>No token at all:</strong> does the baseline request even require one?</li>
      <li><strong>Remove / empty / randomize the token:</strong> <code>csrf=</code>, no <code>csrf</code> parameter, <code>csrf=random-garbage</code> — any of these succeeding means the token isn't actually checked.</li>
      <li><strong>Cross-account binding:</strong> the most reliable test. Get <code>CSRF_A</code> from Account A and <code>CSRF_B</code> from Account B. Try Account A's session with Account B's token. It should fail — if it's accepted, the token isn't bound to the session/user at all.</li>
      <li><strong>Reusability:</strong> replay the same token 2-3 times. A reusable, session-bound token isn't automatically a bug — the real question is whether an attacker can obtain or predict it, and whether it's correctly bound.</li>
      <li><strong>Double-submit cookie pattern:</strong> if the token also arrives as a cookie, check whether an attacker-set cookie value plus a matching parameter value is accepted, and whether that cookie's <code>Domain</code>/<code>Path</code> are scoped tightly enough that another origin or subdomain can't influence it.</li>
    </ul>
  `,
  treeHTML: `
    <div class="tree">
      <div class="tree-root">Found a state-changing request (email / password / role / money / delete…)</div>
      <div class="tree-q">Is a CSRF token present at all?</div>
      <div class="tree-branch">
        <div class="tree-opt tree-no"><span class="tree-tag">NO</span><span class="tree-node tree-fail">Replay the exact request cross-site (PoC form) — if it still succeeds, that's the finding</span></div>
        <div class="tree-opt tree-yes">
          <span class="tree-tag">YES</span><span class="tree-node">Remove it / send empty / send a random value</span>
          <div class="tree-sub">
            <div class="tree-q">Is the token actually validated server-side?</div>
            <div class="tree-branch">
              <div class="tree-opt tree-no"><span class="tree-tag">NO</span><span class="tree-node tree-fail">Vulnerable — the token is decorative, treat it as if it doesn't exist</span></div>
              <div class="tree-opt tree-yes">
                <span class="tree-tag">YES</span><span class="tree-node">Test binding — Account A's token in Account B's session, and vice versa</span>
                <div class="tree-sub">
                  <div class="tree-q">Does a mismatched token still get accepted?</div>
                  <div class="tree-branch">
                    <div class="tree-opt tree-yes"><span class="tree-tag">ACCEPTED</span><span class="tree-node tree-fail">Binding failure — token isn't tied to the session/user</span></div>
                    <div class="tree-opt tree-no"><span class="tree-tag">REJECTED</span><span class="tree-node tree-pass">Move to request-layer checks below</span></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="tree-q">Request-layer fallbacks (test even when the token itself is solid)</div>
      <div class="tree-branch">
        <div class="tree-opt"><span class="tree-node">Method: does <code>POST→GET</code> or a <code>_method=</code> override skip validation?</span></div>
        <div class="tree-opt"><span class="tree-node">Origin/Referer: is a missing or attacker-controlled header accepted?</span></div>
        <div class="tree-opt"><span class="tree-node">Content-Type: does switching to <code>text/plain</code> skip the check some middleware only applies to form-encoded bodies?</span></div>
        <div class="tree-opt"><span class="tree-node">Alternate endpoint: is there a second route to the same state change with weaker or no protection?</span></div>
      </div>
    </div>
  `,
  burpHTML: `
    <ol>
      <li>Capture the state-changing request in Proxy, send it to Repeater, confirm the baseline 200/success.</li>
      <li>Right-click the request → <strong>Engagement tools → Generate CSRF PoC</strong>. Burp builds the auto-submitting HTML form for you — edit the generated form field values if you want to change the forged data (e.g. the attacker's email), save it as an <code>.html</code> file, and open it in a browser logged into the target.</li>
      <li>In Repeater, strip the <code>csrf</code> parameter entirely, then try an empty value, then a random string — three quick sends to answer "is it validated at all."</li>
      <li>For the cross-account test: log Account A and Account B into two Repeater tabs (or two browser profiles), copy each one's token, and swap them between sessions.</li>
      <li>Use Repeater's "Change request method" right-click option to flip <code>POST→GET</code> in one click and see if the same parameters still work as a query string.</li>
      <li>Strip or rewrite the <code>Origin</code>/<code>Referer</code> headers directly in Repeater's request editor to test header-based validation independent of the token.</li>
    </ol>
  `,
  extraHTML: `
    <p><strong>Quicker triage without a PoC page:</strong> you can often get a strong early signal with just <code>curl</code>, by sending the request with the session cookie but <em>no</em> <code>Origin</code>/<code>Referer</code> header and a stripped token — the same conditions a true cross-site request would arrive under:</p>
    <pre><code>curl -X POST https://target.example/myaccount/changeemail \\
  -H "Cookie: session=VALID_SESSION" \\
  -d "email=attacker@evil.com"</code></pre>
    <p>If that alone succeeds, you already know enough to build the browser PoC with confidence rather than fishing blind.</p>
    <p>Also check the cookie's <code>SameSite</code> attribute directly in DevTools → Application → Cookies before you assume a PoC will even fire — <code>SameSite=Lax</code> (the modern browser default) already blocks most POST-based CSRF via a simple auto-submitting form, so a real-world PoC against a Lax-cookied target usually needs a top-level navigation or a GET-based state change to actually land. <code>SameSite=Strict</code> blocks cross-site sending entirely in normal navigation. Don't let a missing token alone read as "vulnerable" without checking whether SameSite is already doing the job.</p>
  `,
  reportYesHTML: `the forged cross-site request actually executes the state change against a real test account, the application relies on cookies for auth, and no effective defense (validated token, sufficient SameSite, required re-authentication) is in place — attach the working PoC HTML and a before/after screenshot of the account state.`,
  reportNoHTML: `the token is present, server-validated, and correctly bound to the session/user/action, or the session cookie's <code>SameSite</code> setting already prevents the forged request from firing in current browsers, or the action requires re-entering the password / a fresh 2FA code as a step-up confirmation.`
},

/* ---------------- 2. IDOR / BOLA ---------------- */
{
  id: "idor-bola",
  title: "IDOR / Broken Object Level Authorization (BOLA)",
  category: "Broken Access Control",
  severity: "high",
  descriptionHTML: `
    <p>An Insecure Direct Object Reference happens when the application lets the client specify which object to act on — an ID in a URL, a body parameter, a header — but doesn't check whether the <em>authenticated user</em> is actually allowed to access <em>that specific object</em>. In API terms this is called Broken Object Level Authorization (BOLA): the server answers <code>object_id exists → return object</code> instead of <code>object_id exists AND belongs to this user → return object</code>.</p>
    <p>It shows up anywhere an identifier travels with a request: <code>/api/orders/{id}</code>, <code>?invoice_id=</code>, a hidden form field, a JSON body property, even a custom header — and across every HTTP method, not just GET.</p>
  `,
  impactHTML: `
    <p>Ranges from reading another user's profile name up to full cross-account data exposure or takeover, depending on what the object actually is and which operations are exposed:</p>
    <ul>
      <li><strong>Read:</strong> invoices, private messages, documents, addresses, payment methods, API keys.</li>
      <li><strong>Write:</strong> modifying another user's order, profile, or settings; changing ownership/sharing of a resource you don't own.</li>
      <li><strong>Delete:</strong> removing another user's file, message, or account resource entirely.</li>
      <li><strong>Multi-tenant:</strong> the same flaw across an organization boundary instead of a user boundary is usually rated more severely — one tenant reading another tenant's entire dataset.</li>
    </ul>
  `,
  severityHTML: `
    <p><strong>Medium</strong> for read access to low-sensitivity fields, climbing to <strong>Critical</strong> for write/delete access, financial data, authentication secrets, or any cross-tenant data leak. Classify precisely what's exposed (display name vs. password-reset token vs. full payment details) — that's what actually drives the rating, not the existence of the pattern alone.</p>
  `,
  stepsHTML: `
    <h4 style="margin-top:0">The fundamental two-account test</h4>
    <ol>
      <li>Create two authorized test accounts, A and B.</li>
      <li>Create one object under each: A owns <code>A1</code>, B owns <code>B1</code>.</li>
      <li>Baseline: <code>A session + A1</code> works, <code>B session + B1</code> works.</li>
      <li>Cross the boundary: <code>A session + B1</code> — request it using Account A's session/cookie but Account B's object ID.</li>
    </ol>
    <p>Expected: <code>403</code>/<code>404</code>/<code>401</code>. A <code>200</code> returning B's actual data is the finding. Then repeat in the reverse direction (<code>B session + A1</code>) to confirm it isn't one-directional.</p>

    <h4>Go past read access</h4>
    <p>Test every method the endpoint (or its siblings) supports against the <em>same</em> cross-account object: <code>GET</code>, <code>PUT</code>, <code>PATCH</code>, <code>POST</code>, <code>DELETE</code>. A read-only IDOR and a write/delete IDOR on the same object are different findings worth documenting separately — write access is almost always the stronger one.</p>

    <h4>Nested objects — the easy mistake to miss</h4>
    <p>APIs often check the parent but forget the child:</p>
    <pre><code>GET /api/users/100/orders/500</code></pre>
    <p>The server may confirm <code>user 100</code> exists and is you, but never check that <code>order 500</code> actually <em>belongs to</em> user 100. Test the full combination matrix: your user + your order, your user + someone else's order, someone else's user + your order, someone else's user + their order.</p>

    <h4>Blind IDOR</h4>
    <p>Not every vulnerable endpoint echoes data back. <code>POST /api/order/2001/cancel</code> might just return <code>{"success":true}</code> with no object details — in that case verify impact by checking the object's actual state afterward (does Account B's order now show cancelled?) rather than relying on the response body alone.</p>
  `,
  treeHTML: `
    <div class="tree">
      <div class="tree-root">Found an object identifier (URL / body / header / JSON)</div>
      <div class="tree-q">Does the endpoint require authentication at all?</div>
      <div class="tree-branch">
        <div class="tree-opt tree-no"><span class="tree-tag">NO</span><span class="tree-node">Check whether this object was actually meant to be public — if not, that's an information-disclosure issue, a different class from IDOR</span></div>
        <div class="tree-opt tree-yes">
          <span class="tree-tag">YES</span><span class="tree-node">Create Account A + Account B, each owning their own test object</span>
          <div class="tree-sub">
            <div class="tree-q">Request Account B's object using Account A's session</div>
            <div class="tree-branch">
              <div class="tree-opt tree-deny"><span class="tree-tag">DENIED</span><span class="tree-node tree-pass">Looks correct — but still test write/delete, not just read, before closing it out</span></div>
              <div class="tree-opt tree-allow">
                <span class="tree-tag">ALLOWED (200 + B's data)</span><span class="tree-node tree-fail">Authorization failure candidate</span>
                <div class="tree-sub">
                  <div class="tree-opt"><span class="tree-node">Test every operation independently — READ, WRITE (PUT/PATCH), DELETE each need their own check</span></div>
                  <div class="tree-opt"><span class="tree-node">Test every boundary — User A↔B, Tenant A↔B, normal User→Admin resource</span></div>
                  <div class="tree-opt"><span class="tree-node">Classify the exposed fields — display name vs. payment/auth data decides the severity</span></div>
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
      <li>Log in as Account A and Account B in two separate Repeater tabs so both sessions stay live side by side.</li>
      <li>Capture a request for Account A's own object, send to Repeater, confirm it works.</li>
      <li>Swap in Account B's object ID while keeping Account A's session cookie — this single edit is the entire test.</li>
      <li>Use <strong>Burp Intruder</strong> with the object ID as the payload position and a numeric range (or a list of known test-object IDs) to sweep many IDs quickly under one account's session — useful for confirming the pattern holds across more than one object, not just the one you happened to pick.</li>
      <li>For nested routes, use Repeater to independently vary the URL-path ID and any body/JSON ID in the same request — test every combination, not just the "obvious" one.</li>
      <li>Compare response <strong>length and status code</strong> across the grid of requests (Intruder's results table sorts by these) to spot inconsistent authorization fast, even on a blind endpoint that doesn't obviously echo data.</li>
    </ol>
  `,
  extraHTML: `
    <p><strong>Finding the identifiers in the first place</strong> is often the real bottleneck on a large target — this is where passive recon tooling earns its keep:</p>
    <div class="tool-row"><span class="tname">katana</span><span>Crawls the live app and pulls every URL/parameter it can reach, including ones buried in JS. <code>katana -u https://target.com -jc -d 3 -o katana-urls.txt</code></span></div>
    <div class="tool-row"><span class="tname">gau</span><span>Pulls every URL ever indexed by the Wayback Machine/Common Crawl/OTX for the domain — frequently surfaces old parameter names (<code>user_id=</code>, <code>invoice_id=</code>) still accepted by a live endpoint. <code>gau --subs target.com | grep -iE '(id=|_id=)'</code></span></div>
    <div class="tool-row"><span class="tname">waybackurls</span><span>Same idea, Wayback-only, useful as a second source when <code>gau</code>'s other providers rate-limit. <code>echo target.com | waybackurls | grep '='</code></span></div>
    <p>Once you have a candidate parameter list, grep it against the high-value identifier names (<code>id</code>, <code>uid</code>, <code>user_id</code>, <code>account_id</code>, <code>tenant_id</code>, <code>order_id</code>, <code>document_id</code> …) to prioritize which endpoints to run the two-account test against first, rather than testing every URL by hand.</p>
    <div class="tool-row"><span class="tname">Autorize (Burp extension)</span><span>Automates the two-account comparison for an entire crawled session — configure Account B's cookie once, browse as Account A, and it flags every request that returns 200 for an object it shouldn't.</span></div>
  `,
  reportYesHTML: `Account A's session can read, modify, or delete Account B's object (or vice versa) with no authorization check in between — document the exact request, the two test accounts/objects used, and what was exposed or changed.`,
  reportNoHTML: `cross-account requests are consistently denied (403/404) across every HTTP method and every nested combination you tried, or the object was genuinely intended to be publicly accessible by design (a deliberate share link, for instance) rather than violating the app's own access model.`
}

];
