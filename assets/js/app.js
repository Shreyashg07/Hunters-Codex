/* =========================================================
   THE HUNTER'S CODEX — shared behaviour
   ========================================================= */

(function(){
  "use strict";

  /* ---------- mobile nav ---------- */
  function initNav(){
    var toggle = document.querySelector('[data-nav-toggle]');
    var links = document.querySelector('[data-nav-links]');
    if(!toggle || !links) return;
    toggle.addEventListener('click', function(){
      links.classList.toggle('open');
      var open = links.classList.contains('open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      toggle.textContent = open ? '✕' : '☰';
    });
    links.querySelectorAll('a').forEach(function(a){
      a.addEventListener('click', function(){ links.classList.remove('open'); toggle.textContent = '☰'; });
    });
  }

  /* ---------- theme toggle (light / dark) ---------- */
  function initTheme(){
    var btn = document.querySelector('[data-theme-toggle]');
    function current(){ return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'; }
    function paintIcon(){ if(btn) btn.textContent = current() === 'light' ? '🌙' : '☀'; }
    paintIcon();
    if(!btn) return;
    btn.addEventListener('click', function(){
      var next = current() === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', next);
      try{ localStorage.setItem('codex-theme', next); }catch(e){}
      paintIcon();
    });
  }

  /* ---------- hero rift embers (reads the page's realm colors) ---------- */
  function initEmbers(){
    var wrap = document.querySelector('[data-embers]');
    if(!wrap) return;
    var cs = getComputedStyle(document.body);
    var colors = [
      cs.getPropertyValue('--accent').trim() || '#00e0ff',
      cs.getPropertyValue('--accent-2').trim() || '#9d7bff',
      cs.getPropertyValue('--accent-3').trim() || '#ff3860'
    ];
    var count = window.innerWidth < 760 ? 10 : 20;
    for(var i=0;i<count;i++){
      var e = document.createElement('span');
      e.className = 'ember';
      e.style.left = (55 + Math.random()*42) + '%';
      e.style.bottom = (10 + Math.random()*20) + '%';
      e.style.animationDelay = (Math.random()*7) + 's';
      e.style.animationDuration = (5 + Math.random()*4) + 's';
      var c = colors[i % colors.length];
      e.style.background = c;
      e.style.boxShadow = '0 0 8px 2px ' + c;
      wrap.appendChild(e);
    }
  }

  /* ---------- realm particle canvas (the "realistic" animated background) ---------- */
  function initRealmCanvas(){
    var canvas = document.querySelector('[data-realm-canvas]');
    if(!canvas || !canvas.getContext) return;
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if(reduce) return; /* the static gradient layer alone is enough motion */

    var ctx = canvas.getContext('2d');
    var realm = document.body.getAttribute('data-realm') || 'default';
    var cs = getComputedStyle(document.body);
    var palette = [
      cs.getPropertyValue('--accent-rgb').trim()  || '0,224,255',
      cs.getPropertyValue('--accent2-rgb').trim() || '157,123,255',
      cs.getPropertyValue('--accent3-rgb').trim() || '255,56,96'
    ];

    var W, H, DPR, particles, centers, shootingStar, lightning, echoes, t = 0;

    function resize(){
      DPR = Math.min(window.devicePixelRatio || 1, 2);
      W = window.innerWidth; H = window.innerHeight;
      canvas.width = W * DPR; canvas.height = H * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      seed();
    }

    function seed(){
      var base = Math.min(60, Math.max(22, Math.floor(W / 24)));
      if(W < 640) base = Math.floor(base * 0.55);
      particles = [];
      for(var i = 0; i < base; i++){
        particles.push(makeParticle());
      }
      centers = [
        { x: W * 0.22, y: H * 0.35 },
        { x: W * 0.78, y: H * 0.65 }
      ];
      shootingStar = null;
      lightning = null;
      echoes = [];
    }

    function makeParticle(spawnEdge){
      var rgb = palette[Math.floor(Math.random() * palette.length)];
      var p = {
        x: Math.random() * W,
        y: spawnEdge ? H + 10 : Math.random() * H,
        r: 0.8 + Math.random() * (realm === 'hulk' ? 2.2 : 1.6),
        rgb: rgb,
        vx: (Math.random() - 0.5) * 0.18,
        vy: (Math.random() - 0.5) * 0.14,
        phase: Math.random() * Math.PI * 2,
        speed: 0.4 + Math.random() * 0.8,
        baseA: 0.35 + Math.random() * 0.45,
        angle: Math.random() * Math.PI * 2,
        orbitR: 40 + Math.random() * Math.min(W, H) * 0.28,
        orbitSpeed: (0.1 + Math.random() * 0.25) * (Math.random() < 0.5 ? -1 : 1)
      };
      if(realm === 'hulk') p.vy = -Math.abs(p.vy) - 0.05; /* gamma motes drift up */
      return p;
    }

    function drawParticle(p, alpha){
      ctx.beginPath();
      ctx.fillStyle = 'rgba(' + p.rgb + ',' + alpha.toFixed(3) + ')';
      ctx.shadowColor = 'rgba(' + p.rgb + ',0.9)';
      ctx.shadowBlur = p.r * 3.2;
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
    }

    function step(){
      t += 1;
      ctx.clearRect(0, 0, W, H);

      if(realm === 'ironman'){
        /* orbital motes around two repulsor-like focal points */
        particles.forEach(function(p, i){
          var c = centers[i % centers.length];
          p.angle += p.orbitSpeed * 0.01;
          var r = p.orbitR + Math.sin(t * 0.01 + p.phase) * 10;
          p.x = c.x + Math.cos(p.angle) * r;
          p.y = c.y + Math.sin(p.angle) * r * 0.72;
          var a = p.baseA * (0.6 + 0.4 * Math.sin(t * 0.02 * p.speed + p.phase));
          drawParticle(p, a);
        });
        centers.forEach(function(c){
          var pulse = 60 + Math.sin(t * 0.02) * 8;
          var grad = ctx.createRadialGradient(c.x, c.y, 0, c.x, c.y, pulse);
          grad.addColorStop(0, 'rgba(' + palette[0] + ',0.10)');
          grad.addColorStop(1, 'rgba(' + palette[0] + ',0)');
          ctx.fillStyle = grad;
          ctx.beginPath(); ctx.arc(c.x, c.y, pulse, 0, Math.PI * 2); ctx.fill();
        });
      } else {
        /* drifting field, shared by hulk / wakanda / cap / default */
        particles.forEach(function(p){
          p.x += p.vx; p.y += p.vy;
          if(realm === 'hulk'){ p.vx += (Math.random() - 0.5) * 0.01; }
          if(p.x < -10) p.x = W + 10; if(p.x > W + 10) p.x = -10;
          if(p.y < -10){ Object.assign(p, makeParticle(false)); p.y = H + 10; }
          if(p.y > H + 10){ if(realm === 'hulk'){ Object.assign(p, makeParticle(true)); } else { p.y = -10; } }
          var a = p.baseA * (0.55 + 0.45 * Math.sin(t * 0.02 * p.speed + p.phase));
          drawParticle(p, a);
        });

        if(realm === 'wakanda'){
          /* vibranium network mesh: connect nearby particles with faint lines */
          ctx.lineWidth = 0.6;
          for(var i = 0; i < particles.length; i++){
            for(var j = i + 1; j < particles.length; j++){
              var dx = particles[i].x - particles[j].x, dy = particles[i].y - particles[j].y;
              var dist = Math.sqrt(dx * dx + dy * dy);
              if(dist < 130){
                ctx.strokeStyle = 'rgba(' + palette[0] + ',' + (0.14 * (1 - dist / 130)).toFixed(3) + ')';
                ctx.beginPath();
                ctx.moveTo(particles[i].x, particles[i].y);
                ctx.lineTo(particles[j].x, particles[j].y);
                ctx.stroke();
              }
            }
          }
        }

        if(realm === 'thor'){
          /* rare jagged lightning bolt, strikes top-to-bottom and flashes out */
          if(!lightning && Math.random() < 0.006){
            var sx = Math.random() * W, cy = -10, segs = [{ x: sx, y: cy }], cx = sx;
            var steps = 6 + Math.floor(Math.random() * 4);
            for(var s = 0; s < steps; s++){
              cx += (Math.random() - 0.5) * 90;
              cy += H / steps;
              segs.push({ x: cx, y: cy });
            }
            lightning = { segs: segs, life: 0 };
          }
          if(lightning){
            lightning.life++;
            var la = Math.max(0, 1 - lightning.life / 14);
            if(la > 0){
              ctx.strokeStyle = 'rgba(' + palette[0] + ',' + la.toFixed(3) + ')';
              ctx.lineWidth = 2; ctx.lineJoin = 'round';
              ctx.shadowColor = 'rgba(' + palette[0] + ',0.9)'; ctx.shadowBlur = 16;
              ctx.beginPath();
              lightning.segs.forEach(function(pt, idx){ if(idx === 0) ctx.moveTo(pt.x, pt.y); else ctx.lineTo(pt.x, pt.y); });
              ctx.stroke();
              ctx.shadowBlur = 0;
            } else { lightning = null; }
          }
        }

        if(realm === 'loki'){
          /* illusion clones: a particle occasionally casts a faint duplicate that drifts its own way and dissolves */
          if(Math.random() < 0.025 && echoes.length < 16 && particles.length){
            var src = particles[Math.floor(Math.random() * particles.length)];
            echoes.push({
              x: src.x, y: src.y, r: src.r * 0.85, rgb: src.rgb,
              vx: (Math.random() - 0.5) * 0.6, vy: (Math.random() - 0.5) * 0.6,
              life: 0, maxLife: 70 + Math.random() * 50
            });
          }
          echoes.forEach(function(e){ e.x += e.vx; e.y += e.vy; e.life++; });
          echoes = echoes.filter(function(e){ return e.life < e.maxLife; });
          echoes.forEach(function(e){ drawParticle(e, 0.3 * (1 - e.life / e.maxLife)); });
        }

        if(realm === 'cap'){
          if(!shootingStar && Math.random() < 0.004){
            shootingStar = { x: Math.random() * W * 0.5, y: Math.random() * H * 0.3, vx: 6 + Math.random() * 3, vy: 3 + Math.random() * 2, life: 0 };
          }
          if(shootingStar){
            shootingStar.x += shootingStar.vx; shootingStar.y += shootingStar.vy; shootingStar.life++;
            var grad = ctx.createLinearGradient(shootingStar.x, shootingStar.y, shootingStar.x - shootingStar.vx * 8, shootingStar.y - shootingStar.vy * 8);
            grad.addColorStop(0, 'rgba(' + palette[2] + ',0.9)');
            grad.addColorStop(1, 'rgba(' + palette[2] + ',0)');
            ctx.strokeStyle = grad; ctx.lineWidth = 2; ctx.lineCap = 'round';
            ctx.beginPath();
            ctx.moveTo(shootingStar.x, shootingStar.y);
            ctx.lineTo(shootingStar.x - shootingStar.vx * 8, shootingStar.y - shootingStar.vy * 8);
            ctx.stroke();
            if(shootingStar.life > 70 || shootingStar.x > W + 40 || shootingStar.y > H + 40) shootingStar = null;
          }
        }
      }

      ctx.shadowBlur = 0;
      raf = requestAnimationFrame(step);
    }

    var raf;
    resize();
    window.addEventListener('resize', resize);
    document.addEventListener('visibilitychange', function(){
      if(document.hidden){ cancelAnimationFrame(raf); }
      else { raf = requestAnimationFrame(step); }
    });
    raf = requestAnimationFrame(step);
  }

  /* ---------- directory card cursor-spotlight ---------- */
  function initCardSpotlight(){
    document.querySelectorAll('.dir-card').forEach(function(card){
      card.addEventListener('mousemove', function(e){
        var r = card.getBoundingClientRect();
        card.style.setProperty('--mx', ((e.clientX - r.left) / r.width * 100) + '%');
        card.style.setProperty('--my', ((e.clientY - r.top) / r.height * 100) + '%');
      });
    });
  }

  /* ---------- severity label + visual-weight maps ---------- */
  var SEV_LABEL = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Informational' };
  var SEV_FILL  = { critical:100, high:80, medium:60, low:35, info:15 };
  var SEV_VAR   = { critical:'var(--crimson)', high:'#ff8e38', medium:'var(--gold)', low:'var(--green)', info:'var(--violet)' };

  /* ---------- generic category icons (original line-art, no licensed IP) ---------- */
  var ICONS = {
    shield:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><polygon points="12,3 19,6 19,12 12,21 5,12 5,6"/></svg>',
    folder:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h3.5l2 2H19a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
    terminal:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><polyline points="7,9 10,12 7,15"/><line x1="13" y1="15" x2="17" y2="15"/></svg>',
    gauge:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M4 17a8 8 0 0 1 16 0"/><line x1="12" y1="17" x2="16" y2="10"/><circle cx="12" cy="17" r="1.3" fill="currentColor" stroke="none"/></svg>'
  };
  function iconFor(category){
    var c = category.toLowerCase();
    if(c.indexOf('injection') !== -1) return ICONS.terminal;
    if(c.indexOf('denial of service') !== -1) return ICONS.gauge;
    if(c.indexOf('auth') !== -1 || c.indexOf('session') !== -1 || c.indexOf('oauth') !== -1 || c.indexOf('access control') !== -1) return ICONS.shield;
    return ICONS.folder; /* misconfiguration / info disclosure / default */
  }

  /* ---------- render a category's vuln list ---------- */
  function renderVulnList(containerId, entries, pageKey){
    var container = document.getElementById(containerId);
    if(!container) return;

    var progress = loadProgress(pageKey);

    entries.forEach(function(item, idx){
      var details = document.createElement('details');
      details.className = 'vuln';
      details.id = item.id;
      details.style.animationDelay = Math.min(idx * 0.05, 0.4) + 's';

      var num = String(idx+1).padStart(2,'0');
      var sevClass = 'sev-' + item.severity;
      var sevText = (SEV_LABEL[item.severity] || item.severity).toUpperCase();
      var sevFill = SEV_FILL[item.severity] || 50;
      var sevVar = SEV_VAR[item.severity] || 'var(--accent)';
      var isDone = !!progress[item.id];

      details.innerHTML =
        '<summary>' +
          '<span class="vuln-id">' + num + '</span>' +
          '<span class="vuln-icon" aria-hidden="true">' + iconFor(item.category) + '</span>' +
          '<div class="vuln-title-wrap">' +
            '<span class="vuln-title">' + item.title + '</span>' +
            '<div class="vuln-badges">' +
              '<span class="badge ' + sevClass + '">' + sevText + '</span>' +
              '<span class="impact-bar" title="Relative severity weight"><span class="impact-bar-fill" style="width:' + sevFill + '%;background:' + sevVar + '"></span></span>' +
              '<span class="cat-badge">' + item.category + '</span>' +
            '</div>' +
          '</div>' +
          '<button type="button" class="vuln-check' + (isDone ? ' done' : '') + '" data-check aria-pressed="' + isDone + '" aria-label="Mark ' + item.title + ' as tested">✓</button>' +
          '<span class="chevron" aria-hidden="true">▾</span>' +
        '</summary>' +
        '<div class="vuln-body">' +
          '<h4>Description</h4>' + item.descriptionHTML +
          '<h4>Impact</h4>' + item.impactHTML +
          '<h4>Severity</h4>' + item.severityHTML +
          '<h4>Steps to Reproduce</h4>' + item.stepsHTML +
          (item.treeHTML ? '<h4>Decision Tree</h4>' + item.treeHTML : '') +
          (item.burpHTML ? '<h4>Testing With Burp Suite</h4>' + item.burpHTML : '') +
          (item.extraHTML ? '<h4>Additional Methodology &amp; Tools</h4>' + item.extraHTML : '') +
          '<h4>Reporting Guidance</h4>' +
          '<div class="callout report-yes"><span class="callout-icon">✓</span><div><b>Report it when</b> — ' + item.reportYesHTML + '</div></div>' +
          '<div class="callout report-no"><span class="callout-icon">✕</span><div><b>Hold off when</b> — ' + item.reportNoHTML + '</div></div>' +
        '</div>';

      container.appendChild(details);

      var checkBtn = details.querySelector('[data-check]');
      checkBtn.addEventListener('click', function(e){
        e.preventDefault();
        e.stopPropagation();
        var nowDone = !checkBtn.classList.contains('done');
        checkBtn.classList.toggle('done', nowDone);
        checkBtn.setAttribute('aria-pressed', nowDone);
        if(nowDone){
          checkBtn.classList.remove('pop');
          void checkBtn.offsetWidth; /* restart animation */
          checkBtn.classList.add('pop');
        }
        progress[item.id] = nowDone;
        saveProgress(pageKey, progress);
        updateProgressBar(pageKey, entries.length);
      });
    });

    updateProgressBar(pageKey, entries.length);
    initFilter(container);
  }

  function loadProgress(pageKey){
    try{
      var raw = localStorage.getItem('codex-progress::' + pageKey);
      return raw ? JSON.parse(raw) : {};
    }catch(e){ return {}; }
  }
  function saveProgress(pageKey, obj){
    try{ localStorage.setItem('codex-progress::' + pageKey, JSON.stringify(obj)); }catch(e){}
  }
  function updateProgressBar(pageKey, total){
    var fill = document.querySelector('[data-progress-fill]');
    var label = document.querySelector('[data-progress-label]');
    if(!fill || !label) return;
    var progress = loadProgress(pageKey);
    var done = Object.keys(progress).filter(function(k){ return progress[k]; }).length;
    var pct = total ? Math.round((done/total)*100) : 0;
    fill.style.width = pct + '%';
    label.textContent = done + ' / ' + total + ' tested';
  }

  /* ---------- live filter (animated dim-out, not an instant hide) ---------- */
  function initFilter(scopeEl){
    var input = document.querySelector('[data-filter]');
    if(!input || input.dataset.wired) return;
    input.dataset.wired = 'true';
    input.addEventListener('input', function(){
      var q = input.value.trim().toLowerCase();
      document.querySelectorAll('.vuln').forEach(function(v){
        var text = v.textContent.toLowerCase();
        var matches = !q || text.indexOf(q) !== -1;
        v.classList.toggle('filtered-out', !matches);
      });
    });
  }

  /* ---------- scroll reveal: fade/rise sections in as they enter view ---------- */
  function initScrollReveal(){
    /* dir-card/vuln already animate in via their own CSS keyframe the
       moment they're created — this is for the plainer section-head/panel
       elements that currently just appear with no motion at all. */
    var targets = document.querySelectorAll('.section-head, .panel');
    if(!targets.length) return;
    if(!('IntersectionObserver' in window)){
      targets.forEach(function(t){ t.classList.add('reveal','in-view'); });
      return;
    }
    var io = new IntersectionObserver(function(entries){
      entries.forEach(function(entry){
        if(entry.isIntersecting){
          entry.target.classList.add('in-view');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
    targets.forEach(function(t){ t.classList.add('reveal'); io.observe(t); });
  }

  /* ---------- hero stat count-up ---------- */
  function initStatCountUp(){
    document.querySelectorAll('.stat b').forEach(function(el){
      var raw = el.textContent.trim();
      var match = raw.match(/^(\d+)(.*)$/);
      if(!match) return;
      var target = parseInt(match[1], 10);
      var digits = match[1].length;
      var suffix = match[2] || '';
      var start = null;
      var duration = 1200;
      function step(ts){
        if(start === null) start = ts;
        var p = Math.min((ts - start) / duration, 1);
        var eased = 1 - Math.pow(1 - p, 3);
        el.textContent = String(Math.round(target * eased)).padStart(digits, '0') + suffix;
        if(p < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    });
  }

  document.addEventListener('DOMContentLoaded', function(){
    initNav();
    initTheme();
    initEmbers();
    initRealmCanvas();
    initCardSpotlight();
    initScrollReveal();
    initStatCountUp();
  });

  window.Codex = { renderVulnList: renderVulnList };
})();
