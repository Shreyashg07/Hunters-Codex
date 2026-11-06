/* ============================================================
   API & BUSINESS LOGIC
   Race conditions — when a check-then-act sequence isn't atomic,
   and enough simultaneous requests can all slip through the gap
   between the check and the act.
   ============================================================ */

var BUSINESS_LOGIC = [

/* ---------------- 1. RACE CONDITIONS ---------------- */
{
  id: "race-condition",
  title: "Race Conditions (Limit-Overrun / TOCTOU)",
  category: "Business Logic / Concurrency",
  severity: "high",
  descriptionHTML: `
    <p>A race condition exists when the server reads some state — a balance, a redemption count, a login-attempt counter, stock on hand — and then writes a change based on it, but the "check" and the "act" aren't one atomic operation. If enough identical requests arrive within that narrow gap, the server can read the <em>same</em> "before" state for several of them at once, and let all of them proceed even though only one (or a fixed number) should have been allowed. This is the classic time-of-check-to-time-of-use (TOCTOU) flaw, applied to web application business logic rather than a filesystem.</p>
    <p>It's the same underlying gap a rate-limit bypass exploits — "RT-04: concurrency and atomic counters" — but the pattern shows up anywhere an operation is meant to happen <em>exactly once</em> or <em>up to N times</em>, not just on rate limiters.</p>
  `,
  impactHTML: `
    <ul>
      <li><strong>Financial:</strong> redeem a single-use coupon, gift card, or referral bonus many times over; withdraw or transfer more than the account's actual balance (double-spend); apply a one-time discount code repeatedly.</li>
      <li><strong>Security-control bypass:</strong> race a login/OTP/password-reset attempt limit so more guesses land than the stated policy allows — the exact RT-04 scenario, with authentication impact attached.</li>
      <li><strong>Inventory/state:</strong> buy the last unit of stock multiple times over (oversell/negative inventory); redeem a one-time invite or referral code to create more accounts than intended.</li>
      <li><strong>Integrity:</strong> cast more than one vote/like/rating where the UI and most of the backend assume exactly one per user; create duplicate orders from a single checkout click.</li>
    </ul>
  `,
  severityHTML: `
    <p><strong>Medium</strong> for a low-value duplicate action (an extra like, a harmlessly duplicated non-financial record). <strong>High → Critical</strong> the moment it touches money (double-spend, coupon abuse), inventory integrity, or a security control whose entire purpose is limiting attempts (OTP, login, password reset) — in that last case, the race condition is really an authentication-control bypass wearing a concurrency bug's clothes.</p>
  `,
  stepsHTML: `
    <h4 style="margin-top:0">1. Find check-then-act candidates</h4>
    <p>Look for any endpoint where the server's response depends on reading some mutable state first:</p>
    <div class="checklist">
      <ul>
        <li>Coupon / voucher / gift-card redemption</li>
        <li>Referral or invite code usage</li>
        <li>Wallet balance, withdrawal, transfer, or purchase</li>
        <li>Login, OTP, and password-reset attempt counters</li>
        <li>Voting, liking, rating, upvote/downvote toggles</li>
        <li>Stock/inventory purchase, especially near the last unit</li>
        <li>One-time password-reset or email-verification tokens</li>
        <li>Account creation tied to a unique email/phone that should only succeed once</li>
        <li>Follow/subscribe toggle buttons</li>
        <li>Any multi-step flow where a later step trusts state a prior step recorded</li>
      </ul>
    </div>
    <p>Endpoints with noticeably <strong>higher latency</strong> (a DB write plus an external API call or email send before the response returns) are good candidates — more time between the check and the act means a wider window for a race to land.</p>

    <h4>2. Baseline the intended behavior</h4>
    <p>Perform the action once, normally, and confirm the expected limit — a coupon marks itself used, a 6th OTP attempt gets rejected, a purchase decrements stock by exactly one. This is what "it worked" and "it didn't" need to be measured against once you start racing requests.</p>

    <h4>3. Fire the requests as close to simultaneously as realistically possible</h4>
    <p>Naive parallel <code>curl</code> commands or a basic threaded script often <em>don't</em> reproduce a real race — separate TCP connections pick up enough natural jitter (DNS, handshake, OS scheduling) that requests usually still serialize at the server, giving a false negative. The reliable modern technique is the <strong>single-packet attack</strong>: open connections to the target, send everything except the final bytes of each request, then release all the final bytes together in one write so every request lands in essentially the same read window on the server. See the Burp Suite section below — this is built in now, you don't need to hand-roll it.</p>
    <p>Start with a modest batch (5–20 concurrent requests) against a low-risk part of the flow before scaling up, and stay inside whatever request volume the program's scope allows.</p>

    <h4>4. Verify the real consequence, not just the response codes</h4>
    <p>A <code>200</code> on every raced request doesn't automatically mean all of them actually took effect, and a <code>429</code>/error on some doesn't automatically mean they were correctly blocked — check the real state afterward: did the coupon's "used" flag only need to fire once but the discount applied three times? Did the account balance actually go negative? Did more than the stated number of OTP attempts actually get validated against the correct code? That verified state change is the entire finding — the race is just how you got there.</p>
  `,
  treeHTML: `
    <div class="tree">
      <div class="tree-root">Found a check-then-act operation (balance→debit, redemption→mark-used, attempt-count→verify, stock→decrement…)</div>
      <div class="tree-q">Send N identical requests landing as simultaneously as possible (single-packet attack / Turbo Intruder)</div>
      <div class="tree-q">How many of the N actually took effect?</div>
      <div class="tree-branch">
        <div class="tree-opt tree-deny"><span class="tree-tag">EXACTLY THE INTENDED LIMIT</span><span class="tree-node tree-pass">Correctly serialized — not vulnerable, at least at this concurrency level</span></div>
        <div class="tree-opt tree-allow">
          <span class="tree-tag">MORE THAN THE INTENDED LIMIT</span><span class="tree-node tree-fail">Race condition confirmed</span>
          <div class="tree-sub">
            <div class="tree-opt"><span class="tree-node">Verify the real-world state change — balance, redemption count, attempt count, stock level — not just response codes</span></div>
            <div class="tree-opt"><span class="tree-node">Document: which check-then-act gap, how many requests raced through out of how many sent, and the concrete, verified consequence</span></div>
          </div>
        </div>
      </div>
    </div>
  `,
  burpHTML: `
    <ol>
      <li>Capture the target request in Proxy, send it to Repeater.</li>
      <li>Duplicate the tab as many times as the requests you want to race (or use Burp's "Send group" workflow — select several Repeater tabs, right-click → <strong>Add tab to group</strong>).</li>
      <li>With the group selected, use <strong>"Send group in parallel"</strong> — current Burp Suite builds implement the single-packet attack automatically for grouped requests, holding each one back and releasing them together rather than firing them one after another.</li>
      <li>Compare the responses across the group — if more than the intended number show a genuine success (not just a <code>200</code>, but the actual expected success body/behavior), you've likely landed the race.</li>
      <li>Re-run a couple of times — a race is probabilistic, not deterministic, so a single miss doesn't rule it out and a single hit is worth reproducing before you trust it.</li>
    </ol>
  `,
  extraHTML: `
    <div class="tool-row"><span class="tname">Turbo Intruder</span><span>The standard tool for higher-precision or larger-scale race testing — ships with a race-condition example script using its <code>engine=Engine.BURP2</code> / single-packet-capable engine, which queues every request and releases them in one burst. Load it via Burp's Extender/BApp, point it at the captured request, and set the concurrent-request count.</span></div>
    <p><strong>Why naive parallel requests often fail to reproduce a real race:</strong> this is the "single-packet attack" research (PortSwigger/James Kettle) in one sentence — separate HTTP/1.1 connections each pick up their own DNS/TCP/TLS jitter, so "simultaneous" curl commands usually still arrive at the server milliseconds apart, which is often enough time for the check-then-act gap to serialize correctly and hide the bug. Holding every request's final bytes back and releasing them together removes that jitter, which is exactly what Burp's group-send and Turbo Intruder's race engine do for you.</p>
    <p><strong>HTTP/2 helps too:</strong> if the target negotiates HTTP/2, multiple requests can multiplex over a single connection, which naturally lands them closer together than separate HTTP/1.1 connections would — worth checking which protocol you're actually testing over.</p>
  `,
  reportYesHTML: `more requests succeed than the stated or obviously-intended limit allows, and you've verified the actual state change — not just response codes — proving the consequence (extra redemptions, a negative balance, more validated attempts than the policy states).`,
  reportNoHTML: `the server consistently allows only the intended number through regardless of how tightly you time the requests, or the "duplicate" successes you saw were a client-side/response artifact rather than a verified server-side state change — re-check with the single-packet technique before concluding it's not racy, since naive parallel requests are a common source of false negatives here.`
}

];
