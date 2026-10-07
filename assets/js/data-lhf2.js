/* ============================================================
   LOW HANGING FRUITS — PART 2
   Auth-flow and account-lifecycle weaknesses.
   ============================================================ */

var LHF2 = [

/* ---------------- 1. HTML INJECTION IN EMAIL ---------------- */
{
  id: "html-injection-email",
  title: "HTML Injection in Transactional Email",
  category: "Injection (HTML Injection)",
  severity: "low",
  descriptionHTML: `
    <p>Many apps drop user-supplied values (first name, last name, username, company name) straight into transactional emails — "Hi, {name}!", welcome mails, OTP/verification emails — without encoding them. If the app doesn't HTML-encode that value before rendering the email template, you can inject arbitrary HTML/markup that shows up in the victim's inbox exactly as you wrote it.</p>
  `,
  impactHTML: `
    <p>Because the email appears to come from the legitimate, trusted sender, injected content is highly convincing. A classic PoC is replacing your display name with a fake link (<code>evil.com</code> styled as a "verify your account" button) so the rendered email shows "Hi, <a href="#">evil.com</a>" or a full fake call-to-action — setting up a phishing vector that rides on the target's own sender reputation. Most email clients strip <code>&lt;script&gt;</code>, so this is markup/link injection rather than full JS-executing XSS, but it's still a real deception/phishing primitive and is commonly rewarded.</p>
  `,
  severityHTML: `<p><strong>Low → Medium.</strong> Rises toward Medium if you can inject a convincing fake button/link that redirects to an attacker-controlled domain, or if it reaches high-trust emails like password-reset or security-alert notifications rather than just a welcome message.</p>`,
  stepsHTML: `
    <ol>
      <li>Create (or edit) an account and set the injectable field — first name, last name, display name, company — to an HTML payload, e.g.:
        <pre><code>&lt;a href="https://evil.com"&gt;Click here to verify&lt;/a&gt;
&lt;img src=x&gt;
&lt;b&gt;Account Suspended&lt;/b&gt;</code></pre>
      </li>
      <li>Trigger any flow that emails that field back to the user — welcome email, OTP email, "someone logged in as {name}" alert, invoice/receipt email, referral email.</li>
      <li>Check the received email's rendered HTML (view source in your mail client) — if the tag rendered instead of being shown as literal text (<code>&amp;lt;a href...&amp;gt;</code>), it's vulnerable.</li>
    </ol>
    <p><strong>Valid bug:</strong> your markup renders as live HTML in the email (a real clickable link, bold/suspicious text, a broken fake image). <strong>Not a bug:</strong> the payload is shown as escaped plain text, or the email template strips/sanitizes HTML tags before sending.</p>
  `,
  extraHTML: `
    <p>Don't stop at the name field — any user-controlled value that gets echoed into any outbound email is a candidate:</p>
    <ul>
      <li>Profile fields: bio, company, job title, address.</li>
      <li>"Invite a friend" / referral emails (your name shows up in an email sent <em>to someone else</em> — often a stronger PoC since the victim never had an account).</li>
      <li>Support ticket subject/body that gets auto-emailed to an agent.</li>
      <li>Order/shipping details that appear on receipt or confirmation emails.</li>
      <li>Any "notify me" or digest email that includes user-generated content.</li>
    </ul>
    <p>Test both plaintext-looking fields (name) and fields already expected to contain some formatting (bio/about) — the latter is more likely to pass through a rich-text pipeline that under-sanitizes.</p>
    <p><strong>Also test:</strong> whether inline <code>style</code> attributes survive (<code>&lt;div style="..."&gt;</code>) — some HTML-sanitizing mail pipelines strip tags but leave attributes untouched, letting you overlay or visually hide legitimate content with CSS even without a working link injection.</p>
  `,
  reportYesHTML: `your injected markup renders as live HTML in the delivered email — especially if it reaches another victim (referral/invite flow) rather than only your own inbox, or if it lands in a high-trust transactional email.`,
  reportNoHTML: `the payload is rendered as escaped literal text, or the email pipeline strips tags/attributes before sending — confirm by actually viewing the received email's source, not just the account's web profile page (the web page and the email template are often sanitized differently).`
},

/* ---------------- 2. WEAK PASSWORD POLICY ---------------- */
{
  id: "weak-password-policy",
  title: "Weak Password Policy",
  category: "Broken Authentication",
  severity: "low",
  descriptionHTML: `
    <p>Checks whether the registration/password-change flow actually enforces a reasonable password policy — minimum length, complexity, and resistance to trivially guessable values — and whether login attempts are rate-limited at all.</p>
  `,
  impactHTML: `
    <p>Weak policies make accounts easier to brute-force or guess outright, and make credential-stuffing (reusing breached password lists against this app) far more effective. On its own this is a low-friction finding; combined with <strong>no rate limiting</strong> it becomes a genuinely exploitable account-takeover vector.</p>
  `,
  severityHTML: `<p><strong>Low</strong> standalone (policy gap). <strong>Medium</strong> when no rate limiting/lockout exists alongside it — that combination is what actually enables an attack, not the weak policy in isolation.</p>`,
  stepsHTML: `
    <h4 style="margin-top:0">Test cases</h4>
    <ul>
      <li><strong>Short passwords:</strong> does <code>1</code>, <code>ab</code>, or a 4-character password get accepted?</li>
      <li><strong>Common patterns:</strong> <code>password</code>, <code>123456</code>, <code>qwerty</code>, <code>Password1</code> — does the app check against a common-password/breach list (HaveIBeenPwned Pwned Passwords API is the standard here) or accept anything that technically meets length rules?</li>
      <li><strong>No character-class requirement:</strong> all-lowercase, all-digits, no symbol required.</li>
      <li><strong>Using the email/username as the password:</strong> does it block this obvious case?</li>
      <li><strong>No rate limiting / account lockout:</strong> script 20-50 login attempts with wrong passwords via Burp Intruder — does the app throttle, CAPTCHA, or lock after a threshold, or let you try indefinitely?</li>
      <li><strong>No maximum length sanity floor</strong> check too (tie-in with the long-password DoS entry) — some apps cap length so low (e.g. 8 max) that it artificially shrinks the keyspace.</li>
    </ul>
  `,
  extraHTML: `
    <p>Other angles worth covering in the same report:</p>
    <ul>
      <li>Password confirmation field bypass — does the API endpoint itself enforce the same rules as the UI's JS validation, or can you skip the frontend and POST a weak password directly?</li>
      <li>Password reuse — can you "change" your password back to the exact same one repeatedly, defeating any password-history policy the app claims to have?</li>
      <li>CAPTCHA presence/absence specifically on the login endpoint after repeated failures, separate from registration.</li>
    </ul>
    <p><strong>Don't confuse this with brute-forcing a single account:</strong> also test <strong>password spraying</strong> — a handful of common passwords (<code>Welcome1</code>, <code>Password123</code>) tried across many different usernames, one attempt per account. This evades per-account lockout entirely and is the more realistic real-world attack when the policy is weak.</p>
  `,
  reportYesHTML: `the app accepts trivially weak passwords (short, common, username-as-password) <em>and</em> has no meaningful rate limiting/lockout on login — report the combination with a clear brute-force PoC where possible.`,
  reportNoHTML: `the app enforces reasonable minimum complexity, or weak passwords are allowed but strong rate limiting/CAPTCHA/lockout makes brute-forcing impractical — many programs treat policy-gap-alone (no exploitable path) as Informational.`
},

/* ---------------- 3. EMAIL VERIFICATION BYPASS ---------------- */
{
  id: "email-verification-bypass",
  title: "Email Verification Bypass",
  category: "Broken Authentication",
  severity: "high",
  descriptionHTML: `
    <p>Apps that require email verification before granting full account access sometimes have a second entry path — most commonly OAuth/social login — that doesn't enforce the same check. If logging in via Google/GitHub/etc. with the same (unverified) email address grants full access, you've bypassed verification entirely without ever proving you own the mailbox.</p>
  `,
  impactHTML: `
    <p>Email verification exists to prove account ownership and prevent account-squatting/impersonation using an email you don't control. A bypass lets an attacker register with a victim's email (one they don't own), never verify it, pivot through a loosely-connected OAuth path, and land in a "trusted/verified" state — potentially merging with or shadowing the real owner's eventual account.</p>
  `,
  severityHTML: `<p><strong>Medium → High</strong>, scaling with what unverified-but-"trusted" access actually grants — read/write to sensitive data, payment methods, or the ability to later take over the legitimate account when the real owner signs up pushes this toward High.</p>`,
  stepsHTML: `
    <ol>
      <li>Register a new account with email + password using an email address you control but <strong>do not click the verification link</strong>.</li>
      <li>Log out.</li>
      <li>Go to the login page and authenticate via an OAuth provider (Google/Microsoft/GitHub) using that <em>same</em> email address.</li>
      <li>Check whether the app treats you as fully verified/trusted now — does it still show "please verify your email," or did the OAuth login silently flip the verified flag?</li>
    </ol>
    <p>The underlying flaw: the app trusts "the OAuth provider vouches for this email" implicitly, without checking whether <em>that specific email</em> was already independently verified (or not) through the app's own flow, and without checking whether the OAuth provider itself confirms the email as verified on their end.</p>
  `,
  extraHTML: `
    <p>Other bypass patterns worth checking, since "OAuth path" is only one variant:</p>
    <ul>
      <li><strong>Predictable/decodable verification tokens:</strong> is the token a Base64-encoded user ID or email (<code>echo -n "verify:123" | base64</code>-style), an incrementing integer, an MD5/SHA1 of something guessable (email + fixed salt), or a short numeric OTP with no rate limit? Decode a few sample tokens and look for a pattern before assuming they're random.</li>
      <li><strong>Direct state manipulation:</strong> after registering, check if an authenticated API call (e.g. <code>PATCH /api/user</code> with <code>{"email_verified": true}</code>) is naively trusted from the client.</li>
      <li><strong>Response manipulation:</strong> does the verification-check API return a boolean client-side that a proxy can flip (<code>"verified": false</code> → <code>true</code>) before the frontend reads it?</li>
      <li><strong>Race condition:</strong> fire the verification-required action and the verification-confirmation request concurrently — some implementations check the flag before the DB write from a parallel request lands.</li>
      <li><strong>Username/email re-registration:</strong> register, don't verify, then re-register the exact same email through a different flow (invite link, SSO-only signup) and see if the second path silently treats the first as verified.</li>
    </ul>
    <p><strong>Also test invite-based flows:</strong> if an existing user can invite someone by email, does accepting that invite grant verified status without ever proving control of the inbox — i.e. does simply clicking the link (which anyone with access to a forwarded or leaked link could do) count as verification?</p>
  `,
  reportYesHTML: `you can reach a fully-trusted/verified account state for an email you were never actually required to prove ownership of — document the exact path (OAuth, token decode, API manipulation) that skipped verification.`,
  reportNoHTML: `all entry paths independently and correctly check the same verification flag server-side, or unverified accounts are genuinely restricted (read-only, no sensitive actions) regardless of which login method was used.`
},

/* ---------------- 4. PASSWORD RESET TOKEN REUSE ---------------- */
{
  id: "password-reset-token-reuse",
  title: "Password Reset Token Reuse",
  category: "Broken Authentication",
  severity: "high",
  descriptionHTML: `
    <p>A password-reset token should be single-use and short-lived — once it's used (or a newer one is requested), the old token must stop working. This entry covers the several distinct ways that invalidation can be missing.</p>
  `,
  impactHTML: `
    <p>A reset token that stays valid after use, or that never expires, is effectively a standing password for the account that an attacker only needs to capture once — via a referrer leak, a shared inbox, shoulder-surfing, or a logging/analytics tool that happened to record the URL.</p>
  `,
  severityHTML: `<p><strong>High</strong> — this directly enables account takeover and is one of the most consistently well-rewarded findings in this entire checklist.</p>`,
  stepsHTML: `
    <h4 style="margin-top:0">Test case 1 — requesting a new token should kill the old one</h4>
    <ol>
      <li>Trigger "forgot password" → get reset link 1. Don't use it yet.</li>
      <li>Trigger "forgot password" again on the same account → get reset link 2.</li>
      <li>Use link 1 (the older, supposedly superseded one) to actually reset the password.</li>
      <li><strong>Valid bug</strong> if link 1 still works — the app isn't invalidating prior tokens when a new one is issued.</li>
    </ol>

    <h4>Test case 2 — reuse after a successful reset</h4>
    <p>Use a reset link once to successfully change the password, then try the <em>exact same link</em> a second time. It should be rejected outright — if it still loads the reset form and lets you set yet another password, that's a bug on its own (and compounds test case 1).</p>

    <h4>Test case 3 — expiry window</h4>
    <p>Note the stated expiry (if disclosed in the email, e.g. "valid for 1 hour") and test the actual enforced window with Burp's clock, or just by waiting — do tokens genuinely expire, or do they silently remain valid days later? Also check: does the token expire based on <em>issue time</em> correctly, or does some action (like visiting the link without submitting) incorrectly reset/extend its lifetime?</p>

    <h4>Other variants to try</h4>
    <ul>
      <li><strong>Token not bound to the requesting user/session</strong> — can token for user A be submitted while authenticated/associated as user B?</li>
      <li><strong>Token leaked via Referer header</strong> — if the reset page loads third-party resources (analytics, fonts, images) after the token is in the URL, check whether it leaks in the <code>Referer</code> header to those third parties.</li>
      <li><strong>Host Header Injection in the reset email</strong> — does the reset link's domain come from a trusted, hardcoded value server-side, or does it reflect the request's <code>Host</code>/<code>X-Forwarded-Host</code> header? If the latter, you can potentially get a victim's token sent to an attacker-controlled domain by poisoning the host header on their reset request.</li>
      <li><strong>Weak token generation</strong> — short numeric codes, predictable sequences, or tokens derived from guessable values (timestamp + user ID hashed with no secret) rather than a long cryptographically random string.</li>
    </ul>
  `,
  extraHTML: `
    <div class="tool-row"><span class="tname">Burp Sequencer</span><span>Feed it a batch of captured reset tokens to statistically test randomness/entropy — a token that looks random but scores poorly here is practically guessable at scale. Proxy → Sequencer → paste tokens → Analyze.</span></div>
  `,
  reportYesHTML: `a used or superseded token still works, tokens don't expire within a reasonable window, or the reset link's domain can be poisoned via Host header manipulation — any of these independently qualifies.`,
  reportNoHTML: `tokens are strictly single-use, expire quickly, and are invalidated the moment a newer one is issued — a token that's merely long-lived but genuinely single-use and well-randomized is a weaker finding, worth noting but not critical on its own.`
},

/* ---------------- 5. OAUTH SIGNUP ACCOUNT CONFUSION ---------------- */
{
  id: "oauth-signup-bug",
  title: "OAuth Signup Account Confusion",
  category: "Broken Authentication / OAuth Misconfiguration",
  severity: "high",
  descriptionHTML: `
    <p>Checks whether signing up via email+password and later via an OAuth provider (Google, etc.) using the <em>same email address</em> are correctly treated as the <strong>same account</strong> — or whether the app silently creates two separate accounts under one email, or worse, merges into the existing account without verifying the OAuth login actually belongs to that email's rightful owner.</p>
  `,
  impactHTML: `
    <p>Two realistic bad outcomes, both documented repeatedly in public bug bounty writeups: (1) a confusing split-identity state where data/sessions get mixed up between "the same person's" two accounts, or (2) far more seriously, an attacker who doesn't own a victim's email can sign up via an OAuth provider that itself doesn't strictly verify the email (or where the attacker controls a look-alike/unverified email on that provider) and get auto-merged into — or silently linked to — the victim's existing password-based account, leading to account takeover.</p>
  `,
  severityHTML: `<p><strong>Medium → High</strong>, scaling directly with whether the merge/link step properly re-verifies the email or not. If OAuth login alone (with no re-verification step) grants access to a pre-existing password-based account's full data, that's a <strong>High</strong>, bounty-worthy account takeover.</p>`,
  stepsHTML: `
    <ol>
      <li>Sign up normally with email + password using a test email you control.</li>
      <li>Log out.</li>
      <li>Go through "Sign in with Google" (or whichever OAuth provider is offered) using that <em>exact same email address</em>.</li>
      <li>Observe the result:
        <ul>
          <li>Does it log you straight into the <strong>same existing account</strong> with no additional verification step? (Worth asking: is that acceptable, since you genuinely own the email either way in this specific test — but is there a scenario where you wouldn't?)</li>
          <li>Does it create a brand-new, <strong>separate</strong> account instead — leaving two disconnected accounts under one email, which is a logic/UX bug and occasionally a data-isolation concern?</li>
          <li>Does it ask you to confirm/link by entering the <em>existing account's password</em> before merging — this is the secure pattern.</li>
        </ul>
      </li>
    </ol>
  `,
  extraHTML: `
    <p>The more serious variant to specifically test for: find (or use a second test account on) an OAuth/identity provider that allows an <strong>unverified email</strong> to be asserted during the OAuth flow, or one where you can register an email you don't actually own and the provider still passes it along. If the target app trusts that assertion and auto-merges/logs you into an account that already exists under that email — <strong>without an independent re-verification step</strong> — that's a genuine account-takeover path, not just a UX quirk. Document precisely which OAuth provider was used and whether its own email was independently verified by that provider.</p>
    <p><strong>Also test with Burp:</strong> intercept the OAuth callback/token-exchange response and see if the app trusts a client-supplied <code>email</code>/<code>email_verified</code> field at face value rather than re-querying the provider's userinfo endpoint server-side — a classic OAuth misconfiguration that directly enables this kind of account confusion.</p>
  `,
  reportYesHTML: `OAuth login silently grants access to (or merges into) a pre-existing account without any re-verification step, especially where the OAuth provider's own email verification is weak or can be spoofed — this is a real account-takeover path.`,
  reportNoHTML: `the app requires explicit account linking (password confirmation, or a verification email) before connecting an OAuth login to an existing account, or correctly keeps them as clearly separate accounts with no cross-account data leakage.`
},

/* ---------------- 6. BROKEN LINK HIJACKING ---------------- */
{
  id: "broken-link-hijacking",
  title: "Broken Link Hijacking",
  category: "Security Misconfiguration",
  severity: "low",
  descriptionHTML: `
    <p>Broken Link Hijacking (BLH) exists whenever a target links out to a resource — a social media profile, an external script/CDN file, an old analytics or partner page — that has since expired or been deleted. Because the destination is gone, anyone can register that same username/domain/handle and take over what the target's own site still links to, trading on its trust.</p>
  `,
  impactHTML: `
    <p>Impact depends heavily on <em>what kind</em> of link is broken:</p>
    <ul>
      <li><strong>Dead social media link</strong> (Twitter/X, Instagram, Facebook, TikTok handle the company no longer owns) — an attacker registers the same handle and impersonates the company for phishing/reputation damage. Lower severity, but consistently accepted on most programs.</li>
      <li><strong>Dead external JS/CDN include</strong> — if the target's page still has <code>&lt;script src="https://expired-domain.com/lib.js"&gt;</code> and that domain can be re-registered, whoever controls it now controls JavaScript execution in the context of the target's site — effectively <strong>stored XSS</strong>. This is a much higher-severity variant of the same root issue.</li>
      <li><strong>Dead CDN/file-hosting links without <code>rel="nofollow"</code></strong> — can sometimes be reclaimed to host attacker content under a trusted-looking path.</li>
    </ul>
  `,
  severityHTML: `<p><strong>Low → Medium</strong> for a dead social link. <strong>High → Critical</strong> if the dead link is an externally-hosted script/resource actively included by the page — that's a stored-XSS-equivalent finding, not just a dead link, and should be reported/framed as such.</p>`,
  stepsHTML: `
    <ol>
      <li>Browse the site normally and Ctrl+Click (open-in-new-tab) every outbound icon/link — social footer icons, "partners," "press," blog "read more on Medium," old API docs, third-party widgets.</li>
      <li>Note anything that resolves to a <strong>404</strong>, a domain-for-sale parking page, a "this account doesn't exist" page, or an NXDOMAIN.</li>
      <li>For a 404/does-not-exist result: check whether the handle/domain is actually available to register (don't assume — verify on the platform/registrar). <strong>Available + currently linked from the target = valid finding. Still taken or just temporarily down = not a bug.</strong></li>
      <li>For any <code>&lt;script&gt;</code>/<code>&lt;link&gt;</code> tag pointing to an external host: specifically check if that host's domain is expired/available via <code>whois</code> — this is the highest-impact variant and worth prioritizing.</li>
    </ol>
  `,
  extraHTML: `
    <div class="tool-row"><span class="tname">BrokenLinkHijacker (BLH)</span><span>Purpose-built for this exact bug class — crawls a site and collects all outbound/social links across configurable crawl depth. <code>git clone https://github.com/MayankPandey01/BrokenLinkHijacker.git &amp;&amp; cd BrokenLinkHijacker</code><br><code>python BLH.py https://target.com</code> — default depth 1<br><code>python BLH.py https://target.com -d 2</code> — crawl one level deeper<br><code>python BLH.py https://target.com -o True</code> — save results to <code>domain_links.txt</code></span></div>
    <div class="tool-row"><span class="tname">socialhunter</span><span>Focused specifically on broken <em>social media</em> links (Twitter/Facebook/Instagram/TikTok) across a list of crawled URLs. <code>go install github.com/utkusen/socialhunter@latest</code><br><code>socialhunter -f urls.txt -w 10</code></span></div>
    <div class="tool-row"><span class="tname">broken-link-checker</span><span>General-purpose npm crawler, good for a first-pass sweep of every outbound link on a site. <code>npm install broken-link-checker -g</code><br><code>blc https://target.com -ro</code></span></div>
    <p>Background reading: edoverflow's original write-up on this bug class is the reference most triagers cite — <code>edoverflow.com/2017/broken-link-hijacking</code>.</p>
    <p><strong>Also check archived versions:</strong> pull historical URLs via <code>gau</code>/<code>waybackurls</code> or <code>web.archive.org</code> directly — a dead link from a years-old version of the page can still be reachable today through an old cached path or sitemap entry, even if it's gone from the current homepage.</p>
  `,
  reportYesHTML: `the destination (handle, domain, or script host) is genuinely available for you to register right now, and the target's live page still actively links to or includes it — screenshot both the dead destination and the live reference on the target's page as PoC.`,
  reportNoHTML: `the link resolves fine, the handle/domain is still owned by someone (even if unrelated), or the "broken" link only existed in an old cached/archived version of the page and isn't actually present on the live site anymore.`
}

];
