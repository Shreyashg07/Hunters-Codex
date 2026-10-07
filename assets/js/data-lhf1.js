/* ============================================================
   LOW HANGING FRUITS — PART 1
   Recon-adjacent misconfigurations and session hygiene basics.
   ============================================================ */

var LHF1 = [

/* ---------------- 1. ORIGIN IP DISCLOSURE ---------------- */
{
  id: "origin-ip-disclosure",
  title: "Origin IP Disclosure",
  category: "Security Misconfiguration",
  severity: "low",
  descriptionHTML: `
    <p>Most production targets sit behind a reverse proxy, CDN, or WAF (Cloudflare, Akamai, AWS CloudFront + WAF, Sucuri, Imperva). That layer is meant to be the <em>only</em> public door — it filters malicious traffic, rate-limits abuse, and hides the real backend ("origin") server's IP address. Origin IP disclosure is when that real IP leaks anyway, through DNS history, certificate metadata, mail records, or a misconfigured subdomain that was never put behind the proxy.</p>
    <p>On its own, knowing an IP is just information. It becomes a bug the moment you can prove the origin is <strong>directly reachable and unprotected</strong> — i.e. the WAF/CDN sitting in front of it can be walked around entirely.</p>
  `,
  impactHTML: `
    <p>If the origin accepts direct connections without IP allow-listing (only trusting the CDN's published ranges), an attacker can:</p>
    <ul>
      <li>Send requests straight to the origin and <strong>skip every WAF rule</strong> — SQLi/XSS filters, bot protection, geo-blocking, rate limiting.</li>
      <li>Launch a volumetric or application-layer DoS directly at the origin, bypassing the CDN's DDoS absorption entirely.</li>
      <li>Reach other services exposed on the same box — SSH, RDP, database ports, internal admin panels — that were never meant to face the internet.</li>
    </ul>
  `,
  severityHTML: `
    <p>Usually <strong>Informational → Low</strong> on its own. Most programs explicitly won't reward "I found an IP that resolves" — they want proof the WAF is actually bypassable. It moves to <strong>Medium</strong> once you demonstrate a payload the CDN blocks succeeds unfiltered against the raw IP, or the origin exposes unrelated services via a port scan. Always check the program's scope — some explicitly exclude "CDN/WAF bypass without further impact."</p>
  `,
  stepsHTML: `
    <h4 style="margin-top:0">Quick (and usually dead-end) check</h4>
    <pre><code>ping target.com
nslookup target.com</code></pre>
    <p>On a CDN-fronted site this almost always just returns the CDN's own edge IP — treat it as a sanity check, not a finding.</p>

    <h4>DNS history</h4>
    <ul>
      <li><code>crt.sh?q=target.com</code> — certificate transparency logs can surface old A records or subdomains issued before the CDN was put in front.</li>
      <li><code>dnsdumpster.com</code>, <code>securitytrails.com</code>, <code>viewdns.info/iphistory</code> — historical DNS resolution.</li>
    </ul>

    <h4>Shodan &amp; Censys — cert and content matching</h4>
    <div class="dork-list">
      <code>ssl.cert.subject.cn:"target.com"</code>
      <code>http.html:"&lt;title&gt;Target Brand Name&lt;/title&gt;"</code>
      <code>http.favicon.hash:&lt;mmh3-hash-of-their-favicon&gt;</code>
    </div>
    <p>Censys equivalent:</p>
    <div class="dork-list">
      <code>services.tls.certificates.leaf_data.subject.common_name: "target.com"</code>
    </div>
    <p>The favicon-hash technique is reliable because the real origin usually still serves the exact same favicon even when nothing else matches. Compute the hash with <code>fav-up</code> (below) or a quick <code>mmh3</code> script and search it directly on Shodan.</p>

    <h4>Un-proxied subdomains</h4>
    <p>Run normal subdomain recon (<code>subfinder</code>, <code>amass</code>, <code>assetfinder</code>) then check which hostnames resolve to an IP <em>outside</em> the CDN's known ranges — <code>mail.</code>, <code>ftp.</code>, <code>direct.</code>, old <code>staging.</code>/<code>dev.</code> hosts are classic offenders:</p>
    <pre><code>subfinder -d target.com -silent | dnsx -silent -resp
# cross-check each IP's ASN against the CDN's published ranges</code></pre>
    <p>Mail server IPs (from MX / SPF records) are also worth a look — they're frequently hosted on the same subnet as the real origin.</p>

    <h4>Validating a candidate IP — is that 200 OK actually real?</h4>
    <p><strong>A plain 200 response proves nothing by itself.</strong> Shared hosting boxes will often return 200 for <em>any</em> Host header, or serve a completely unrelated site. Confirm it properly before you report anything:</p>
    <pre><code># 1. Force the real Host header against the candidate IP
curl -s -o /dev/null -w "%{http_code}\\n" -H "Host: target.com" https://&lt;candidate-ip&gt;/ -k

# 2. Compare the TLS certificate served directly on the IP
openssl s_client -connect &lt;candidate-ip&gt;:443 -servername target.com &lt;/dev/null 2&gt;/dev/null \\
  | openssl x509 -noout -subject -issuer -dates</code></pre>
    <ul>
      <li><strong>Valid finding:</strong> the page content, title, login form, and response headers match the real site almost exactly, <em>and</em> the TLS cert's SAN list includes the real domain.</li>
      <li><strong>Not valid:</strong> you get a default "Welcome to nginx/Apache" page, a totally different company's site, a generic "domain not configured" catch-all, or a redirect straight back to the CDN.</li>
    </ul>
    <p><strong>The step that actually proves impact:</strong> send a request that the CDN/WAF would normally block — a basic <code>' OR 1=1 --</code> or <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> test payload, or an endpoint you know is rate-limited at the edge — directly at the IP with the correct Host header. If it goes through unfiltered where the CDN domain blocks or throttles it, you've proven a real WAF bypass, not just an IP leak.</p>
  `,
  extraHTML: `
    <div class="tool-row"><span class="tname">CloudFlair</span><span>Automates the Censys-cert-matching technique end to end. <code>git clone https://github.com/christophetd/CloudFlair.git &amp;&amp; cd CloudFlair &amp;&amp; python cloudflair.py target.com</code> (needs a free Censys API key).</span></div>
    <div class="tool-row"><span class="tname">fav-up</span><span>Origin-finding via favicon hash across Shodan. <code>python3 favUp.py -w target.com -o out.txt -fh</code></span></div>
    <div class="tool-row"><span class="tname">hakoriginfinder</span><span>Feed it a candidate IP list (from <code>asnmap</code>/<code>mapcidr</code>) and it scores each response against the public site. <code>cat ips.txt | hakoriginfinder -h target.com</code></span></div>
    <div class="tool-row"><span class="tname">CrimeFlare</span><span>Older PHP-based origin lookup, hit or miss on modern setups. <code>git clone https://github.com/zidansec/CrimeFlare.git &amp;&amp; php crimeflare.php</code></span></div>
    <div class="tool-row"><span class="tname">ZoomEye</span><span>A second cert/banner search engine worth cross-checking against Shodan/Censys — different crawl coverage sometimes surfaces a candidate the other two miss. Query: <code>ssl.cert.subject:"target.com"</code>.</span></div>
    <p>Once an origin is <em>confirmed</em>, the test cases worth running against it (never outside program scope/DoS policy):</p>
    <ul>
      <li>Replay any payload the CDN normally blocks or rate-limits, directly at the IP, and diff the behaviour.</li>
      <li>Light, scope-respecting port scan (<code>nmap -Pn -p- --min-rate 500 &lt;ip&gt;</code>) to see what else the box exposes — an open DB port or admin panel turns this into a much stronger report.</li>
      <li>Check whether the origin firewall is IP-allow-listed to the CDN ranges at all — if direct traffic is accepted from any source, that's the core misconfiguration to document.</li>
      <li><strong>Also try non-standard ports directly</strong> against candidate IPs with the same Host-header technique — <code>8080</code>, <code>8443</code>, <code>2082</code>/<code>2083</code> (cPanel) often still answer even when 80/443 are properly firewalled to the CDN only.</li>
    </ul>
  `,
  reportYesHTML: `you can demonstrate the origin is reachable over the internet <em>and</em> that it meaningfully bypasses a protection the CDN/WAF provides (a blocked payload succeeds, rate limits don't apply, or unrelated services are exposed).`,
  reportNoHTML: `you've only resolved an IP with no further proof — the origin firewall still only trusts the CDN's ranges, the IP serves an unrelated/default page, or the program's policy explicitly excludes WAF-bypass-only findings.`
},

/* ---------------- 2. DIRECTORY LISTING ---------------- */
{
  id: "directory-listing",
  title: "Directory Listing",
  category: "Security Misconfiguration",
  severity: "medium",
  descriptionHTML: `
    <p>Directory listing (a.k.a. directory browsing) happens when a web server has no <code>index.html</code>/<code>index.php</code> in a folder <em>and</em> the server is configured to render a file index instead of returning <code>403 Forbidden</code>. Visiting the folder directly shows every file inside it — exactly like running <code>ls</code> over HTTP.</p>
  `,
  impactHTML: `
    <p>Impact scales entirely with what's sitting in the exposed folder:</p>
    <ul>
      <li>Just a plain asset folder with nothing sensitive → cosmetic, Informational.</li>
      <li>Backup archives, <code>.sql</code> dumps, <code>.env</code>/config files, <code>.git</code> internals, or private keys → source code disclosure, credential leakage, sometimes a direct path to full compromise.</li>
    </ul>
  `,
  severityHTML: `
    <p><strong>Low/Informational</strong> for an empty or non-sensitive index. <strong>Medium</strong> when it reveals internal structure, filenames, or old/test files. <strong>High</strong> when it exposes credentials, source, database dumps, or a <code>.git</code> directory you can reconstruct with <code>git-dumper</code>.</p>
  `,
  stepsHTML: `
    <h4 style="margin-top:0">Manual checks</h4>
    <ul>
      <li><strong>Direct directory access:</strong> strip the filename from a known URL (<code>/images/logo.png</code> → <code>/images/</code>) and see if a file index renders instead of a 403/404.</li>
      <li><strong>Missing index document:</strong> probe folders you'd expect to exist but that likely have no <code>index.html</code>/<code>index.php</code> of their own, and confirm the server correctly falls back to 403 rather than listing.</li>
      <li><strong>Common asset folders:</strong> <code>/images/</code>, <code>/assets/</code>, <code>/uploads/</code>, <code>/css/</code>, <code>/js/</code>, <code>/scripts/</code>, <code>/backup/</code>, <code>/backups/</code>, <code>/old/</code>, <code>/tmp/</code>, <code>/logs/</code>, <code>/.git/</code>, <code>/.svn/</code>, <code>/config/</code>, <code>/private/</code>, <code>/vendor/</code>, <code>/node_modules/</code>, <code>/wp-content/uploads/</code>.</li>
    </ul>

    <h4>Google dorks</h4>
    <div class="dork-list">
      <code>site:target.com intitle:"index of /"</code>
      <code>site:target.com intitle:"index of" "parent directory"</code>
      <code>site:target.com intitle:"index of" "backup"</code>
      <code>site:target.com intitle:"index of" "config.php"</code>
      <code>site:target.com intitle:"index of" ".env"</code>
      <code>site:target.com intitle:"index of" "wp-config.php.bak"</code>
      <code>site:target.com intitle:"index of" "*.sql"</code>
      <code>site:target.com intitle:"index of" "id_rsa"</code>
      <code>site:target.com inurl:"/.git" intitle:"index of"</code>
      <code>site:target.com filetype:env "DB_PASSWORD"</code>
      <code>site:target.com filetype:sql "insert into"</code>
      <code>site:target.com filetype:log</code>
      <code>site:target.com (filetype:bak OR filetype:old OR filetype:backup OR filetype:swp)</code>
      <code>site:target.com inurl:/admin intitle:"index of"</code>
      <code>site:target.com intitle:"index of" "credentials"</code>
    </div>

    <h4>Filenames worth brute-forcing once a listable folder is found</h4>
    <div class="dork-list">
      <code>backup.zip · backup.tar.gz · backup.sql · db.sql · database.sql · dump.sql</code>
      <code>config.php · config.php.bak · config.old · wp-config.php.bak · .env · .env.bak</code>
      <code>.git/HEAD · .git/config · .svn/entries</code>
      <code>id_rsa · id_rsa.pub · .htpasswd · .htaccess · web.config</code>
      <code>login.php · admin.php · test.php · phpinfo.php · debug.log · error_log</code>
      <code>.DS_Store · Thumbs.db · composer.json · package.json</code>
    </div>
  `,
  extraHTML: `
    <div class="tool-row"><span class="tname">dirsearch</span><span>The standard brute-forcer. <code>pip3 install dirsearch</code> then: <code>dirsearch -u https://target.com -e php,html,js,txt,bak,zip,git,env,sql,old -x 403,404</code></span></div>
    <div class="tool-row"><span class="tname">dirsearch (crawl mode)</span><span><code>dirsearch -u https://target.com --crawl -x 400,404</code> — follows links it finds to discover more paths as it goes.</span></div>
    <div class="tool-row"><span class="tname">ffuf</span><span><code>ffuf -u https://target.com/FUZZ -w /path/to/SecLists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,403</code></span></div>
    <div class="tool-row"><span class="tname">gobuster</span><span><code>gobuster dir -u https://target.com -w wordlist.txt -x php,bak,zip,env -b 404</code></span></div>
    <div class="tool-row"><span class="tname">git-dumper</span><span>If <code>/.git/</code> is exposed, this reconstructs the entire repo (source, commit history, old secrets) from the raw objects: <code>git-dumper https://target.com/.git/ ./dump</code></span></div>
    <p>SecLists' <code>Discovery/Web-Content</code> wordlists (<code>raft-large-directories.txt</code>, <code>quickhits.txt</code>) pair well with any of the above for coverage beyond the defaults.</p>
    <div class="tool-row"><span class="tname">gau</span><span>Pulls every URL the Wayback Machine/Common Crawl ever indexed for the domain — a goldmine for paths that were listable once and may still be live today. <code>gau --subs target.com | grep -iE '\\.(sql|zip|bak|env|git|log)$'</code></span></div>
    <p><strong>Also worth a direct look:</strong> <code>web.archive.org/web/*/target.com/*</code> — a directory locked down today may still show its old file index in a years-old snapshot, handing you exact filenames to try against the live site.</p>
  `,
  reportYesHTML: `the listing exposes files with real content — backups, source, credentials, <code>.git</code>/<code>.svn</code> internals, logs with PII, or anything you weren't meant to enumerate.`,
  reportNoHTML: `the folder is empty, contains only public static assets (CSS/JS/images already linked from the page), or the server correctly returns 403/404 and you just found the raw path.`
},

/* ---------------- 3. SESSION MANAGEMENT (password reset invalidation) ---------------- */
{
  id: "session-management-reset",
  title: "Session Management — No Invalidation on Password Reset",
  category: "Broken Authentication",
  severity: "medium",
  descriptionHTML: `
    <p>When a user changes or resets their password, every <em>other</em> active session for that account should be killed — otherwise the whole point of a password reset (locking out someone who had access) is defeated. This checks whether the app actually invalidates existing sessions server-side when the password changes, rather than just changing the password and leaving old sessions alive.</p>
  `,
  impactHTML: `
    <p>If an attacker already has an active session (stolen cookie, shared device, leaked token) and the victim "secures" their account by resetting the password, the attacker's session should die immediately. If it doesn't, the password reset gives a false sense of security — the attacker keeps full access regardless of the new password.</p>
  `,
  severityHTML: `<p><strong>Medium</strong>, trending <strong>High</strong> if sensitive actions (email change, 2FA disable, payment info) remain possible from the stale session.</p>`,
  stepsHTML: `
    <ol>
      <li>Log into the same account from two browsers (or one normal + one incognito window) — call them Browser A and Browser B.</li>
      <li>In Browser A, go through "change password" (or "forgot password" → reset link → set new password).</li>
      <li>Without logging out of Browser B, refresh it and try to perform an action — view the dashboard, change an email, hit an authenticated API endpoint.</li>
      <li><strong>Valid bug:</strong> Browser B is still fully logged in and can act on the account after the password change.<br><strong>Not a bug:</strong> Browser B is immediately kicked to the login page or its session token is rejected server-side.</li>
    </ol>
  `,
  extraHTML: `
    <p>Don't stop at the password field — test session invalidation across every credential-adjacent feature:</p>
    <ul>
      <li><strong>Password reset via "forgot password" flow</strong> (not just the in-account change-password form — these are often implemented separately and can behave differently).</li>
      <li><strong>"Log out of all devices" / "Manage sessions"</strong> — does it actually kill server-side sessions, or just clear the current browser's cookie?</li>
      <li><strong>Email address change</strong> — should also force re-authentication on other sessions in most threat models.</li>
      <li><strong>2FA enable/disable</strong> — toggling MFA should invalidate pre-existing sessions that predate it.</li>
      <li><strong>Account recovery via security questions / backup email</strong> — same invalidation expectation applies.</li>
    </ul>
    <p>Check this at the token level too, with Burp: capture the old session cookie/JWT before the reset, replay it afterward with Repeater, and see if the server actually rejects it rather than the UI simply not showing a logged-in state client-side.</p>
    <p><strong>One more angle:</strong> if there's a "manage active sessions/devices" dashboard, open it in Browser A right after the Browser B password reset — does the old session still appear listed as active, and can you actually revoke it remotely from there? A dashboard that still lists a session the server should've already killed is worth noting even if the session itself turns out to be dead.</p>
  `,
  reportYesHTML: `the old session can still read or write data after the password (or email, or MFA) changes elsewhere — confirm it at the HTTP level, not just "the tab still looks logged in."`,
  reportNoHTML: `the old session is rejected server-side (even if the open tab's UI takes one stale request to catch up), or the app has an explicit, documented "sessions stay alive across password changes" design with its own re-auth for sensitive actions.`
},

/* ---------------- 4. BACK BUTTON ENABLED AFTER LOGOUT ---------------- */
{
  id: "back-button-enabled",
  title: "Back Button Enabled After Logout",
  category: "Broken Authentication",
  severity: "low",
  descriptionHTML: `
    <p>After logging out, hitting the browser's Back button sometimes re-shows a page that looks authenticated — because the browser rendered it from its local cache rather than re-requesting it from the server. The key question isn't "does a stale page appear" (that's a caching header issue), it's "can I still <em>do</em> something authenticated from it."</p>
  `,
  impactHTML: `
    <p>If it's purely a cached render with no live functionality, the practical impact is minimal — mostly a shoulder-surfing concern on shared/public computers. If a genuine authenticated action still succeeds from that cached page, the server never actually terminated the session — that's the real bug.</p>
  `,
  severityHTML: `<p><strong>Low</strong> for a cosmetic stale-cache render. <strong>Medium</strong> if an actual write/read action (not just the page painting) still succeeds against the server after logout.</p>`,
  stepsHTML: `
    <ol>
      <li>Log into the account normally.</li>
      <li>Log out via the app's normal logout flow.</li>
      <li>Press the browser's Back button.</li>
      <li>Don't stop at "the page appeared" — <strong>try to actually do something</strong>: submit a form, click a link that fetches fresh data, hit a button that changes a setting.</li>
    </ol>
    <p><strong>Valid bug:</strong> the page isn't just visually present — a real action (fetching new data, submitting a change) completes successfully against the server. <strong>Not a bug:</strong> the cached DOM is visible but any interaction either fails, redirects to login, or returns a 401/403 — that's just normal browser caching behaviour, not a live session.</p>
  `,
  extraHTML: `
    <p>Check this specifically on the sensitive, high-value flows rather than just the dashboard home:</p>
    <ul>
      <li>Logout itself, then Back → attempt logout <em>again</em> (checking for session fixation across repeated logout calls).</li>
      <li>Account deletion / deactivation pages.</li>
      <li>Payment or billing pages.</li>
      <li>Admin or privileged panels if you have a test account with elevated access.</li>
    </ul>
    <p>On the server side, the fix is <code>Cache-Control: no-store, no-cache, must-revalidate</code> on authenticated responses — worth checking those headers directly in Burp/DevTools Network tab rather than relying on what the browser happens to show.</p>
    <p><strong>Extra check:</strong> specifically rule out the browser's back-forward cache (bfcache) as the only thing you're seeing — in DevTools' Network tab enable "Disable cache" and reload before testing. If an authenticated action still succeeds afterward, bfcache/disk cache is ruled out and you're looking at a genuine server-side session bug, not a browser rendering quirk.</p>
  `,
  reportYesHTML: `you can trigger a genuine server-side action (not just view a cached DOM) from the back-navigated page after logout.`,
  reportNoHTML: `the page is visually present from cache but every real interaction correctly fails or redirects to login — this is standard browser caching, not a session bug, and is rarely accepted on its own.`
},

/* ---------------- 5. SESSION MANAGEMENT USING COOKIES (old cookie reuse) ---------------- */
{
  id: "session-cookie-reuse",
  title: "Session Management via Cookie Reuse",
  category: "Broken Authentication",
  severity: "high",
  descriptionHTML: `
    <p>Logging out should invalidate the session <em>server-side</em> — the token itself should stop being accepted, not just get deleted from the current browser. This test checks whether a session cookie captured before logout still works after logout, confirming the server actually revokes tokens rather than relying on the client to forget them.</p>
  `,
  impactHTML: `
    <p>If old session cookies remain valid indefinitely (or until expiry, which may be weeks), anyone who captured a cookie once — via XSS, a shared/public machine, a proxy log, a malicious browser extension — retains full account access <em>forever</em>, regardless of how many times the legitimate user logs out. This is a classic, well-rewarded finding (CWE-613: Insufficient Session Expiration).</p>
  `,
  severityHTML: `<p><strong>High</strong> — logout is meant to be a hard security boundary. A session that survives it defeats one of the most basic account-protection controls a user has.</p>`,
  stepsHTML: `
    <p><strong>Tools:</strong> a cookie-manager browser extension (e.g. "Cookie-Editor") makes this trivial — no proxy required.</p>
    <ol>
      <li>Log into the target account.</li>
      <li>Open Cookie-Editor, locate the session cookie(s), and export/copy their values somewhere safe.</li>
      <li>Log out normally through the app.</li>
      <li>Log back in (optional — just confirms the account still works normally).</li>
      <li>Open a private/incognito window (or a separate browser profile), navigate to the site, and use Cookie-Editor to <strong>import</strong> the old, pre-logout cookie values.</li>
      <li>Refresh an authenticated page.</li>
    </ol>
    <p><strong>Valid bug:</strong> the imported, supposedly-logged-out session still grants access. <strong>Not a bug:</strong> the old cookie is rejected and you're bounced to login.</p>
  `,
  extraHTML: `
    <p>Worth testing as variants, since some apps handle these differently:</p>
    <ul>
      <li>Does logging out on <strong>one device</strong> invalidate that <em>specific</em> session token, or does it rotate a shared secret that kills <em>every</em> session (different severity/behaviour expectations)?</li>
      <li>If the app uses JWTs: are they validated against a server-side denylist/allowlist on logout, or is logout purely a client-side "delete the cookie" with the JWT itself remaining cryptographically valid until its <code>exp</code> claim? (Stateless JWTs with no revocation list are a very common root cause here — worth naming explicitly in the report.)</li>
      <li>Test the same thing after a password reset, not just a manual logout — same root cause, same impact.</li>
    </ul>
    <p><strong>If the app uses refresh tokens:</strong> capture the refresh token alongside the access token before logout, then after logout try exchanging the old refresh token for a new access token directly at the token endpoint (Burp Repeater). A refresh token that still mints valid new access tokens post-logout is the same bug sitting one layer deeper.</p>
  `,
  reportYesHTML: `a session cookie captured before logout is still accepted by the server afterward — demonstrate it by actually loading authenticated content/performing an action with the old cookie.`,
  reportNoHTML: `the old cookie is immediately rejected post-logout, or the app explicitly documents short-lived, non-revocable tokens as part of a stateless design with compensating controls (very short expiry, refresh-token rotation).`
},

/* ---------------- 6. SPF RECORD NOT FOUND ---------------- */
{
  id: "spf-record-missing",
  title: "SPF Record Not Found",
  category: "Security Misconfiguration",
  severity: "low",
  descriptionHTML: `
    <p>An SPF (Sender Policy Framework) record is a DNS TXT record that lists which mail servers are authorized to send email on behalf of a domain. Receiving mail servers check it to decide whether an incoming message claiming to be from <code>@target.com</code> is legitimate. A missing (or badly configured) SPF record means nothing stops anyone from spoofing email that appears to come from the target's domain.</p>
  `,
  impactHTML: `
    <p>An attacker can send email that appears to originate from <code>support@target.com</code> or similar, enabling highly convincing phishing, business email compromise, or social engineering against the target's own customers/employees — because the "From" domain looks completely legitimate.</p>
  `,
  severityHTML: `
    <p>Usually <strong>Low → Medium</strong>. Many programs now triage bare "SPF missing" reports as Informational/duplicate given how common and low-effort they are to find — but severity rises meaningfully if <strong>DKIM and DMARC are also absent or set to <code>p=none</code></strong> (meaning there's truly nothing stopping spoofed mail from landing in an inbox), and especially if the affected domain is customer-facing (support, billing, no-reply) rather than an obscure internal subdomain.</p>
  `,
  stepsHTML: `
    <h4 style="margin-top:0">Check via <code>dig</code></h4>
    <pre><code>dig TXT target.com +short
# look for a line starting with: v=spf1 ...

dig TXT _dmarc.target.com +short
# look for: v=DMARC1; p=reject  (or p=quarantine)
# p=none or no record at all = weak/no enforcement</code></pre>

    <h4>Check via a validator</h4>
    <p>Go to <code>kitterman.com/spf/validate.html</code>, enter the bare domain (no <code>http://</code> or <code>www</code>), and hit Check SPF. No record shown = vulnerable.</p>

    <h4>What a healthy record looks like</h4>
    <ul>
      <li>Present, and ends in a hard restrictive qualifier: <code>v=spf1 include:_spf.google.com ~all</code> (soft-fail) or ideally <code>-all</code> (hard fail).</li>
      <li>Paired with a DMARC record at <code>p=quarantine</code> or <code>p=reject</code> — SPF alone with no DMARC enforcement is still weak, since many receiving servers accept soft-failed mail anyway.</li>
    </ul>
    <p><strong>What makes it invalid/not worth reporting:</strong> a record exists and ends in <code>-all</code> or <code>~all</code>, DMARC is set to <code>quarantine</code>/<code>reject</code>, and the domain isn't one actually used for outbound mail at all (e.g. a parked marketing subdomain that never sends email — spoofing it has little real-world phishing value).</p>

    <h4>Demonstrating impact (PoC)</h4>
    <p>Use <strong>Emkei's Fake Mailer</strong> (<code>emkei.cz</code>) to actually send a spoofed message and show it lands:</p>
    <ol>
      <li>Open <code>emkei.cz</code>.</li>
      <li>Set "From" to something like <code>Support &lt;support@target.com&gt;</code>.</li>
      <li>Set "To" to a mailbox you control (Gmail, a temp-mail address, or your own test inbox).</li>
      <li>Send, then check the received message's headers — does it land in the inbox (or even spam) showing the spoofed domain, and does the <code>Authentication-Results</code> header show <code>spf=none</code>/<code>spf=softfail</code> rather than a hard fail?</li>
    </ol>
    <p>Note Emkei's mailer is frequently auto-filtered to spam by modern providers regardless of the target's own SPF/DKIM/DMARC posture — a spam-folder landing is still useful evidence (it proves the message wasn't outright <em>rejected</em>), but a clean inbox landing is the strongest possible PoC.</p>
  `,
  extraHTML: `
    <div class="tool-row"><span class="tname">MXToolbox</span><span>One-stop check that also surfaces DKIM selector guesses and any existing blacklist status alongside SPF/DMARC, useful for a fuller picture in the same report. <code>mxtoolbox.com/SuperTool.aspx</code></span></div>
  `,
  reportYesHTML: `the SPF record is genuinely missing (or ends in a permissive <code>+all</code>/no qualifier), DMARC is absent or <code>p=none</code>, the domain is a real outbound-mail-sending domain, and you have a PoC email that was actually accepted/delivered.`,
  reportNoHTML: `a record exists with a hard/soft fail qualifier and DMARC enforcement is in place, or the domain is unused for mail entirely, or the program has already marked this class as informational/out of scope (common — ask or check the policy first).`
},

/* ---------------- 7. LONG PASSWORD / APPLICATION-LAYER DOS ---------------- */
{
  id: "long-password-dos",
  title: "Long Password Application-Layer DoS",
  category: "Denial of Service (Application Layer)",
  severity: "low",
  descriptionHTML: `
    <p>Password hashing algorithms like bcrypt are deliberately slow/CPU-expensive — that's the whole point, it's what makes brute-forcing hard. But if the application doesn't cap input length before hashing, submitting an extremely long password (hundreds of KB to a few MB of characters) forces the server to spend a disproportionate amount of CPU time hashing it, on every single request that includes that field.</p>
  `,
  impactHTML: `
    <p>A single request with an oversized password can measurably slow or time out the handling thread/worker. Sent repeatedly or concurrently, it can degrade the authentication endpoint for other users. This is an <strong>application-level</strong> resource-exhaustion issue (CWE-409/CWE-400) — fundamentally different from a network-level volumetric DDoS.</p>
  `,
  severityHTML: `
    <p>Typically <strong>Low → Medium</strong>, and <strong>DoS findings are out of scope on a large share of bug bounty programs by default</strong> — always check the policy before investing time here. It's generally accepted as a legitimate <em>missing input validation</em> bug (not full DoS) when it causes a clear error or abnormal delay, but rarely paid as a high-severity "DoS" unless you can show it degrades the service for other users, not just the one slow request.</p>
  `,
  stepsHTML: `
    <h4 style="margin-top:0">Manual</h4>
    <p>Register or log in with a password field containing a very large string. A simple way to generate one:</p>
    <pre><code>python3 -c "print('A'*100000)" > longpass.txt   # ~100KB
python3 -c "print('A'*1000000)" > longpass_1mb.txt  # ~1MB</code></pre>
    <p>Submit it in the password field of registration, login, and "change password" — these are often three separate code paths with different validation.</p>

    <h4>With Burp Suite</h4>
    <ol>
      <li>Capture a normal login/register request in Proxy, send it to Repeater.</li>
      <li>Replace the password value with a long payload (use Burp's built-in payload generator or paste a pre-built string).</li>
      <li>Send it and watch the response time and status code. Escalate the length gradually (10KB → 100KB → 1MB) and note where behaviour changes.</li>
      <li>For a slightly stronger PoC, send a handful of these concurrently via Intruder (low thread count, and only within program-authorized rate/DoS testing limits) and watch whether response time for a <em>normal, unrelated</em> request climbs at the same time — that's the evidence of shared-resource impact rather than a one-off slow request.</li>
    </ol>
    <p><strong>What counts as valid:</strong> a <code>500</code> error, a clearly abnormal response time (multiple seconds to tens of seconds for a single request vs. milliseconds normally), or a worker timeout/crash. A request that's simply <code>400 Bad Request</code> with a sane "password too long" validation message is the server working <em>correctly</em> — not a bug.</p>
  `,
  extraHTML: `
    <p><strong>Important scoping note:</strong> this is strictly an <em>application-level</em> resource-consumption issue tied to one expensive operation (password hashing). It is <strong>not</strong> a network-level/volumetric DDoS, and almost every program's policy draws a hard line excluding network-layer DoS entirely. Frame the report explicitly as "missing maximum-length input validation leading to CPU exhaustion on the hashing path," with timing evidence — not as "I can DDoS you," which invites an auto-close.</p>
    <p><strong>Related class worth checking on the same fields:</strong> a field validated with a vulnerable regular expression (email, username) can suffer <strong>ReDoS</strong> — a crafted input exploiting catastrophic backtracking can hang the validator the same way a long password hangs the hasher. Same impact class, different root cause, same test rig (long/crafted input + timing).</p>
  `,
  reportYesHTML: `you get a clear, reproducible abnormal delay or a <code>500</code>/timeout tied directly to password length, with before/after timing evidence, and the program's policy doesn't blanket-exclude DoS-adjacent findings.`,
  reportNoHTML: `the server returns a clean validation error (e.g. 400, "max 128 characters") for long input, or the program's scope explicitly excludes DoS/resource-exhaustion reports — check first, this is one of the most commonly excluded categories.`
}

];
