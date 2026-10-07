/* ============================================================
   BROKEN ACCESS CONTROL
   CSRF and IDOR/BOLA — the two classes where the server trusts
   the client's claim about who's asking, or what they're asking
   for, instead of actually checking. Full checklists included,
   not condensed summaries — work through every sub-checklist.
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
    <p>Walk every "change X" / "add X" / "delete X" flow in the app, especially ones that don't ask for your password again. Search captured traffic for these parameters and features:</p>
    <div class="checklist">
      <div class="checklist-title">☐ State-changing parameters to search for</div>
      <ul>
        <li><code>email</code></li><li><code>password</code></li><li><code>new_password</code></li><li><code>old_password</code></li>
        <li><code>username</code></li><li><code>phone</code></li><li><code>address</code></li><li><code>name</code></li>
        <li><code>role</code></li><li><code>permission</code></li><li><code>is_admin</code></li><li><code>status</code></li>
        <li><code>amount</code></li><li><code>price</code></li><li><code>quantity</code></li><li><code>account</code></li>
        <li><code>user_id</code></li><li><code>target</code></li><li><code>recipient</code></li><li><code>to</code></li>
        <li><code>from</code></li><li><code>message</code></li><li><code>comment</code></li><li><code>content</code></li>
        <li><code>settings</code></li><li><code>notification</code></li><li><code>2fa</code> / <code>mfa</code></li>
        <li><code>api_key</code></li><li><code>redirect</code> / <code>callback</code></li><li><code>delete</code> / <code>action</code> / <code>confirm</code></li>
      </ul>
      <p style="margin:10px 0 0;font-size:0.82rem;color:var(--ink-faint);">Also check application-specific action parameters: <code>?action=change-email</code>, <code>?action=delete-account</code>, <code>?action=transfer</code>, <code>?action=add-user</code>, <code>?action=change-password</code>.</p>
    </div>
    <div class="checklist">
      <div class="checklist-title">☐ Functions &amp; features to test</div>
      <ul>
        <li>Change email</li><li>Change password</li><li>Change username</li><li>Edit profile</li>
        <li>Change phone/address</li><li>Add/remove payment method</li><li>Change account settings</li>
        <li>Enable/disable 2FA</li><li>Change security questions</li><li>Add/remove trusted devices</li>
        <li>Create/delete API keys</li><li>Create/delete users</li><li>Change user roles</li>
        <li>Add/remove permissions</li><li>Account deletion</li><li>Subscription changes</li>
        <li>Order changes</li><li>Address changes</li><li>Message/comment creation</li>
        <li>File/resource deletion</li><li>Administrative actions</li><li>Any money/state transfer</li>
      </ul>
      <p style="margin:10px 0 0;font-size:0.82rem;color:var(--ink-faint);">High priority: anything here that doesn't require re-entering a password or a second confirmation step.</p>
    </div>

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
      <li><strong>Weak/predictable tokens:</strong> are they sequential (<code>123456</code>, <code>123457</code>), short, numeric, timestamp-derived, or built from predictable data like <code>USERID-TIMESTAMP</code>? A secure token is generated from a cryptographically secure random source.</li>
      <li><strong>Parameter manipulation:</strong> also try <code>csrf=null</code>, <code>csrf=undefined</code>, duplicating the parameter (<code>csrf=VALID&amp;csrf=random</code> and the reverse order), case changes, URL/double-encoding, and Unicode edge cases — different layers of the stack sometimes pick the first value, sometimes the last.</li>
      <li><strong>Token location:</strong> identify exactly where it travels — POST parameter, request header (<code>X-CSRF-Token</code>, <code>X-XSRF-TOKEN</code>), cookie, URL parameter, hidden field, or JSON property — and test the same binding/validation questions for whichever location this app uses.</li>
      <li><strong>Double-submit cookie pattern:</strong> if the token also arrives as a cookie, check whether an attacker-set cookie value plus a matching parameter value is accepted, and whether that cookie's <code>Domain</code>/<code>Path</code> are scoped tightly enough that another origin or subdomain can't influence it.</li>
    </ul>
    <p>Use this as the full reference checklist once you've worked the individual tests above — go back through anything unchecked:</p>
    <div class="checklist">
      <div class="checklist-title">☐ Common CSRF bypass categories — full reference</div>
      <div class="checklist-group">
        <div class="checklist-group-title">Token</div>
        <ul>
          <li>No CSRF token</li><li>Token not validated</li><li>Empty token accepted</li>
          <li>Missing token accepted</li><li>Arbitrary token accepted</li><li>Predictable token</li>
          <li>Weak token generation</li><li>Reusable token</li><li>Token not bound to session</li>
          <li>Token not bound to user</li><li>Token not bound to action</li><li>Token duplicated in cookie</li>
          <li>Cookie/token integrity weakness</li><li>CSRF token parameter duplication</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Request layer</div>
        <ul>
          <li>GET instead of POST</li><li>POST instead of expected method</li><li>HTTP method override</li>
          <li>Content-Type variation</li><li>Origin validation bypass</li><li>Missing Origin accepted</li>
          <li>Referer validation bypass</li><li>Missing Referer accepted</li><li>Weak Referer matching</li>
          <li>SameSite weakness</li><li>State-changing GET</li><li>API endpoint missing protection</li>
          <li>Alternate endpoint missing protection</li><li>Alternate parameter missing protection</li>
          <li>Different content parser bypass</li><li>Different HTTP method bypass</li><li>CORS interaction</li>
        </ul>
      </div>
    </div>

    <h4>5. Cookie checklist</h4>
    <div class="checklist single">
      <div class="checklist-group">
        <div class="checklist-group-title">Authentication / session cookies</div>
        <ul><li><code>Secure</code></li><li><code>HttpOnly</code></li><li><code>SameSite</code></li><li><code>Domain</code></li><li><code>Path</code></li></ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">CSRF-related cookies</div>
        <ul><li><code>Secure</code></li><li><code>SameSite</code></li><li><code>Domain</code></li><li><code>Path</code></li></ul>
      </div>
      <p style="margin:8px 0 0;font-size:0.82rem;color:var(--ink-faint);">Pay particular attention to <code>SameSite=None</code> — it explicitly permits cross-site cookie sending (subject to the browser's <code>Secure</code> requirement). SameSite is a defense layer, not a reason to skip testing the application's own CSRF controls — distinguish <code>Lax</code> / <code>Strict</code> / <code>None</code> from the app's actual anti-CSRF design.</p>
    </div>

    <h4>6. Endpoint coverage</h4>
    <div class="checklist">
      <div class="checklist-group">
        <div class="checklist-group-title">Common paths to search traffic for</div>
        <ul>
          <li><code>/account</code></li><li><code>/profile</code></li><li><code>/user</code></li><li><code>/users</code></li>
          <li><code>/settings</code></li><li><code>/preferences</code></li><li><code>/security</code></li><li><code>/password</code></li>
          <li><code>/email</code></li><li><code>/phone</code></li><li><code>/address</code></li><li><code>/payment</code></li>
          <li><code>/billing</code></li><li><code>/order</code></li><li><code>/cart</code></li><li><code>/admin</code></li><li><code>/api</code></li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">State-changing GET patterns — the easiest to trigger cross-site</div>
        <ul>
          <li><code>GET /delete</code></li><li><code>GET /change</code></li><li><code>GET /update</code></li>
          <li><code>GET /enable</code></li><li><code>GET /disable</code></li><li><code>GET /add</code></li>
          <li><code>GET /remove</code></li><li><code>GET /transfer</code></li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">JSON/API routes — don't limit testing to HTML forms</div>
        <ul>
          <li><code>POST /api/user</code></li><li><code>POST /api/profile</code></li><li><code>POST /api/settings</code></li>
          <li><code>PATCH /api/account</code></li><li><code>PUT /api/user</code></li><li><code>DELETE /api/address</code></li>
        </ul>
      </div>
    </div>

    <h4>7. Record a baseline for every endpoint you test</h4>
    <div class="checklist single">
      <ul>
        <li>Endpoint / HTTP method / Authentication</li>
        <li>State-changing action / Parameters</li>
        <li>CSRF parameter name and location</li>
        <li>Origin validation / Referer validation / SameSite</li>
        <li>Content-Type behavior / Method override behavior</li>
        <li>Token lifetime / reusable? / session-bound? / user-bound? / action-bound?</li>
        <li>Result without token / with invalid token / with another user's token</li>
        <li>Result with missing Origin / missing Referer</li>
        <li>Result with alternate method / alternate content type</li>
      </ul>
    </div>
  `,
  treeHTML: `
    <div class="tree">
      <div class="tree-root">CSRF TEST — find a state-changing request (HTML form or API/AJAX, same tests apply either way)</div>
      <div class="tree-q">Is a CSRF token used?</div>
      <div class="tree-branch">
        <div class="tree-opt tree-no"><span class="tree-tag">NO</span><span class="tree-node tree-fail">Test cross-site state change directly — replay the PoC unmodified</span></div>
        <div class="tree-opt tree-yes">
          <span class="tree-tag">YES</span><span class="tree-node">Remove token → empty token → random token</span>
          <div class="tree-sub">
            <div class="tree-q">Is the token validated?</div>
            <div class="tree-branch">
              <div class="tree-opt tree-no"><span class="tree-tag">NO</span><span class="tree-node tree-fail">FAIL — vulnerable, the token is decorative</span></div>
              <div class="tree-opt tree-yes">
                <span class="tree-tag">YES</span><span class="tree-node">Test binding</span>
                <div class="tree-sub">
                  <div class="tree-opt"><span class="tree-node"><strong>Session bound?</strong> — does it survive being used in a different session?</span></div>
                  <div class="tree-opt"><span class="tree-node"><strong>User bound?</strong> — does Account A's token work in Account B's session?</span></div>
                  <div class="tree-opt"><span class="tree-node"><strong>Action bound?</strong> — does a token minted for one action work on a different one?</span></div>
                </div>
                <p style="margin:8px 0 0;font-size:0.84rem;color:var(--ink-faint);">Any "still works" above → binding failure, vulnerable. All correctly rejected → continue below.</p>
                <div class="tree-sub">
                  <div class="tree-q">Test the request layer — all five, independently</div>
                  <div class="tree-branch">
                    <div class="tree-opt"><span class="tree-node"><strong>Method</strong> — does <code>GET</code>↔<code>POST</code> or a <code>_method=</code> override bypass validation?</span></div>
                    <div class="tree-opt"><span class="tree-node"><strong>Origin</strong> — is a missing or invalid <code>Origin</code> header accepted?</span></div>
                    <div class="tree-opt"><span class="tree-node"><strong>Referer</strong> — is a missing or invalid <code>Referer</code> header accepted?</span></div>
                    <div class="tree-opt"><span class="tree-node"><strong>Content-Type</strong> — does an alternate parser (<code>text/plain</code>, <code>multipart/form-data</code>) skip the check?</span></div>
                    <div class="tree-opt"><span class="tree-node"><strong>Cookie</strong> — is <code>SameSite</code> weak/<code>None</code>, or the <code>Domain</code> too broad?</span></div>
                  </div>
                  <p style="margin:8px 0 0;font-size:0.84rem;color:var(--ink-faint);">Finish by checking alternate endpoints/flows that reach the same state change with weaker protection.</p>
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
    <p>It shows up anywhere an identifier travels with a request, and across every HTTP method, not just GET.</p>
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
    <h4 style="margin-top:0">1. Build an object inventory — where identifiers travel</h4>
    <div class="checklist">
      <div class="checklist-group">
        <div class="checklist-group-title">URL / path / query parameters</div>
        <ul>
          <li><code>?id=123</code></li><li><code>?user_id=123</code></li><li><code>?account_id=123</code></li>
          <li><code>?order_id=123</code></li><li><code>?invoice_id=123</code></li><li><code>?document_id=123</code></li>
          <li><code>?file_id=123</code></li><li><code>?message_id=123</code></li>
          <li><code>/user/123</code></li><li><code>/account/123</code></li><li><code>/order/123</code></li>
          <li><code>/document/123</code></li><li><code>/files/123</code></li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Body, JSON, form data &amp; headers</div>
        <ul>
          <li>JSON: <code>{"order_id":123,"status":"..."}</code></li>
          <li>JSON: <code>{"userId":123,"documentId":456}</code></li>
          <li>Form: <code>user_id=123&amp;file_id=456</code></li>
          <li>Header: <code>X-User-ID</code></li><li>Header: <code>X-Account-ID</code></li>
          <li>Header: <code>X-Organization-ID</code></li><li>Header: <code>X-Resource-ID</code></li>
        </ul>
      </div>
      <p style="margin:10px 0 0;font-size:0.82rem;color:var(--ink-faint);">Never assume a header is trustworthy merely because it isn't visible in the URL.</p>
    </div>
    <div class="checklist">
      <div class="checklist-title">☐ Identifier types — note which this target uses</div>
      <ul>
        <li><strong>Sequential integers</strong> (<code>1,2,3…</code>) — highest-value candidate</li>
        <li><strong>UUIDs</strong> — not an authorization mechanism; still test a known UUID from a second test account</li>
        <li><strong>Base64-looking IDs</strong> (<code>MTIzNDU=</code>) — decode and understand what it represents</li>
        <li><strong>Encoded identifiers</strong> — base64 / hex / URL / custom; encoding ≠ authorization</li>
        <li><strong>Composite IDs</strong> (<code>user_123_order_456</code>) — test changing one component at a time</li>
        <li><strong>Hash-like IDs</strong> — don't assume a hash is a secure object reference</li>
      </ul>
    </div>

    <h4>2. The fundamental two-account test</h4>
    <ol>
      <li>Create two authorized test accounts, A and B.</li>
      <li>Create one object under each: A owns <code>A1</code>, B owns <code>B1</code>.</li>
      <li>Baseline: <code>A session + A1</code> works, <code>B session + B1</code> works.</li>
      <li>Cross the boundary: <code>A session + B1</code> — request it using Account A's session/cookie but Account B's object ID.</li>
    </ol>
    <p>Expected: <code>403</code>/<code>404</code>/<code>401</code>. A <code>200</code> returning B's actual data is the finding. Then repeat in the reverse direction (<code>B session + A1</code>) to confirm it isn't one-directional.</p>

    <h4>3. Go past read access</h4>
    <p>Test every method the endpoint (or its siblings) supports against the <em>same</em> cross-account object: <code>GET</code>, <code>PUT</code>, <code>PATCH</code>, <code>POST</code>, <code>DELETE</code>. A read-only IDOR and a write/delete IDOR on the same object are different findings worth documenting separately — write access is almost always the stronger one.</p>

    <h4>4. Nested objects — the easy mistake to miss</h4>
    <p>APIs often check the parent but forget the child:</p>
    <pre><code>GET /api/users/100/orders/500</code></pre>
    <p>The server may confirm <code>user 100</code> exists and is you, but never check that <code>order 500</code> actually <em>belongs to</em> user 100. Test the full combination: your user + your order, your user + someone else's order, someone else's user + your order, someone else's user + their order.</p>

    <h4>5. Blind IDOR</h4>
    <p>Not every vulnerable endpoint echoes data back. <code>POST /api/order/2001/cancel</code> might just return <code>{"success":true}</code> with no object details — verify impact by checking the object's actual state afterward (does Account B's order now show cancelled?) rather than relying on the response body alone.</p>

    <h4>6. The identifier mutation checklist</h4>
    <p>For every identifier you find, run through this:</p>
    <div class="checklist single">
      <ul>
        <li>Increment / decrement the value</li>
        <li>Replace with another known test object's ID</li>
        <li>Replace with another user's test object</li>
        <li>Replace with another tenant's test object</li>
        <li>Change a UUID to a known UUID</li>
        <li>Decode an encoded identifier</li>
        <li>Modify the encoded identifier where appropriate</li>
        <li>Duplicate the parameter (<code>?id=A&amp;id=B</code>)</li>
        <li>Move the identifier from URL → body</li>
        <li>Move the identifier from body → URL</li>
        <li>Test an alternate endpoint for the same object</li>
        <li>Test an alternate HTTP method</li>
      </ul>
      <p style="margin:8px 0 0;font-size:0.82rem;color:var(--ink-faint);">The known-object substitution test is usually more meaningful than blindly incrementing IDs.</p>
    </div>

    <h4>7. The full deep-testing checklist</h4>
    <p>Use this as the actual assessment worksheet — work through every group, not just the two-account read test:</p>
    <div class="checklist">
      <div class="checklist-group">
        <div class="checklist-group-title">Discovery</div>
        <ul>
          <li>Identify object types</li><li>Identify object IDs</li><li>Identify object relationships</li>
          <li>Identify owners</li><li>Identify tenants</li><li>Identify roles</li><li>Identify all CRUD endpoints</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Read</div>
        <ul>
          <li>GET object</li><li>Download object</li><li>Export object</li><li>View object</li>
          <li>Search/filter object</li><li>Nested object</li><li>Attachment</li><li>PDF/CSV/JSON representation</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Write</div>
        <ul>
          <li>POST</li><li>PUT</li><li>PATCH</li><li>Update</li><li>Rename</li><li>Assign</li><li>Transfer</li><li>Share</li><li>Change ownership</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Delete</div>
        <ul>
          <li>DELETE</li><li>Delete endpoint</li><li>Soft delete</li><li>Permanent delete</li><li>Attachment deletion</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Boundaries</div>
        <ul>
          <li>User A → User B</li><li>User B → User A</li><li>Tenant A → Tenant B</li>
          <li>Org A → Org B</li><li>Project A → Project B</li>
          <li>Normal user → Manager</li><li>Normal user → Admin</li><li>Manager → Admin</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Request variants</div>
        <ul>
          <li>URL ID</li><li>Query ID</li><li>Body ID</li><li>JSON ID</li><li>Header ID</li>
          <li>Duplicate ID</li><li>Nested ID</li><li>Alternate HTTP method</li><li>Alternate endpoint</li>
          <li>Alternate API version</li><li>Alternate representation</li><li>Mobile endpoint</li>
          <li>GraphQL endpoint</li><li>WebSocket object reference</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Lifecycle</div>
        <ul>
          <li>Ownership change</li><li>Role change</li><li>User removal</li><li>Tenant removal</li>
          <li>Account deactivation</li><li>Object deletion</li><li>Object archival</li><li>Permission revocation</li>
        </ul>
      </div>
      <div class="checklist-group">
        <div class="checklist-group-title">Validation — compare, don't just read the status code</div>
        <ul>
          <li>Status code</li><li>Response body</li><li>Response length</li><li>Sensitive fields exposed</li>
          <li>Redirect location</li><li>Side effects</li><li>Object state after the request</li>
        </ul>
      </div>
    </div>
    <p>A particularly common real-world pattern worth testing explicitly: <code>/api/users/123</code> is protected, but <code>/api/v2/users/123</code>, <code>/api/internal/users/123</code>, or <code>/api/mobile/users/123</code> isn't — always check alternate API versions and representations (HTML vs JSON vs XML vs PDF vs GraphQL) for the exact same object.</p>
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
    <p>Once you have a candidate parameter list, grep it against the high-value identifier names below to prioritize which endpoints to run the two-account test against first, rather than testing every URL by hand:</p>
    <div class="checklist">
      <div class="checklist-title">☐ High-value IDOR parameter names</div>
      <ul>
        <li><code>id</code></li><li><code>uid</code></li><li><code>user_id</code></li><li><code>userId</code></li>
        <li><code>account_id</code></li><li><code>accountId</code></li><li><code>owner_id</code></li><li><code>ownerId</code></li>
        <li><code>tenant_id</code></li><li><code>tenantId</code></li><li><code>org_id</code></li><li><code>organization_id</code></li>
        <li><code>organizationId</code></li><li><code>workspace_id</code></li><li><code>workspaceId</code></li>
        <li><code>project_id</code></li><li><code>projectId</code></li><li><code>team_id</code></li><li><code>teamId</code></li>
        <li><code>group_id</code></li><li><code>groupId</code></li><li><code>role_id</code></li><li><code>permission_id</code></li>
        <li><code>order_id</code></li><li><code>orderId</code></li><li><code>invoice_id</code></li><li><code>invoiceId</code></li>
        <li><code>transaction_id</code></li><li><code>payment_id</code></li><li><code>document_id</code></li><li><code>documentId</code></li>
        <li><code>file_id</code></li><li><code>fileId</code></li><li><code>attachment_id</code></li><li><code>message_id</code></li>
        <li><code>messageId</code></li><li><code>conversation_id</code></li><li><code>thread_id</code></li><li><code>ticket_id</code></li>
        <li><code>case_id</code></li><li><code>report_id</code></li><li><code>record_id</code></li><li><code>resource_id</code></li>
        <li><code>resourceId</code></li><li><code>object_id</code></li><li><code>objectId</code></li>
      </ul>
      <p style="margin:10px 0 0;font-size:0.82rem;color:var(--ink-faint);">Also search generically for <code>ref</code>, <code>reference</code>, <code>key</code>, <code>uuid</code>, <code>guid</code>, <code>slug</code>, <code>token</code>, <code>code</code>, <code>number</code>, <code>external_id</code>, <code>externalId</code>.</p>
    </div>
    <div class="tool-row"><span class="tname">Autorize (Burp extension)</span><span>Automates the two-account comparison for an entire crawled session — configure Account B's cookie once, browse as Account A, and it flags every request that returns 200 for an object it shouldn't.</span></div>
  `,
  reportYesHTML: `Account A's session can read, modify, or delete Account B's object (or vice versa) with no authorization check in between — document the exact request, the two test accounts/objects used, and what was exposed or changed.`,
  reportNoHTML: `cross-account requests are consistently denied (403/404) across every HTTP method and every nested combination you tried, or the object was genuinely intended to be publicly accessible by design (a deliberate share link, for instance) rather than violating the app's own access model.`
}

];
