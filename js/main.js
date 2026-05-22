// Undependent — Main JavaScript

// ── Hero Terminal Typewriter ──
const heroTerminalLines = [
  { type: 'prompt', text: '$ undep analyze' },
  { type: 'output', text: 'Scanning ~/your-project...' },
  { type: 'output', text: 'Found 47 dependencies across 3 languages' },
  { type: 'output', text: '  • 12 Go modules (go.mod)' },
  { type: 'output', text: '  • 28 npm packages (package.json)' },
  { type: 'output', text: '  • 7 Python packages (requirements.txt)' },
  { type: 'output', text: '' },
  { type: 'output', text: '⚠  3 critical CVEs detected' },
  { type: 'output', text: '⚠  2 viral licenses (GPL, AGPL)' },
  { type: 'output', text: '⚠  5 packages with no maintainer' },
  { type: 'output', text: '' },
  { type: 'output', text: 'Risk Score: 8.7 / 10 — HIGH' },
  { type: 'output', text: '' },
  { type: 'prompt', text: '$ undep inline --pr' },
  { type: 'output', text: '✓ Inlined 47 dependencies' },
  { type: 'output', text: '✓ Lockfile created (SHA256 hashes)' },
  { type: 'output', text: '✓ PR opened: "absorb dependencies"' },
  { type: 'output', text: '' },
  { type: 'output', text: 'Risk Score: 0.0 / 10 — SOVEREIGN' },
];

// Generic typewriter engine — returns { start, reset, isDone }
function createTypewriter(lines, outputEl, speed) {
  let lineIndex = 0;
  let charIndex = 0;
  let currentLine = '';
  let timer = null;
  let done = false;

  function buildHTML(allLines, curIdx, curText, showCursor) {
    let html = '';
    for (let i = 0; i < curIdx; i++) {
      const l = allLines[i];
      const cls = l.type === 'prompt' ? 'prompt' : 'output';
      html += `<span class="${cls}">${l.text}</span>\n`;
    }
    if (curText) {
      const l = allLines[curIdx];
      const cls = l.type === 'prompt' ? 'prompt' : 'output';
      html += `<span class="${cls}">${curText}</span>`;
      if (showCursor) html += '<span class="cursor-blink"></span>';
    }
    return html;
  }

  function type() {
    if (!outputEl) return;
    if (lineIndex >= lines.length) {
      done = true;
      outputEl.innerHTML = outputEl.innerHTML.replace(/<span class="cursor-blink"><\/span>/g, '') + '<span class="cursor-blink"></span>';
      return;
    }
    const line = lines[lineIndex];
    if (charIndex < line.text.length) {
      currentLine += line.text[charIndex];
      charIndex++;
      outputEl.innerHTML = buildHTML(lines, lineIndex, currentLine, true);
      timer = setTimeout(type, speed || (line.type === 'prompt' ? 35 : 12));
    } else {
      lineIndex++;
      charIndex = 0;
      currentLine = '';
      outputEl.innerHTML = buildHTML(lines, lineIndex, '', false);
      timer = setTimeout(type, line.type === 'prompt' ? 600 : 200);
    }
  }

  function reset() {
    if (timer) clearTimeout(timer);
    lineIndex = 0;
    charIndex = 0;
    currentLine = '';
    done = false;
    if (outputEl) outputEl.innerHTML = '';
    setTimeout(type, 300);
  }

  return { start: type, reset, get isDone() { return done; } };
}

// ── Particle Grid Background ──
function initParticleGrid() {
  const canvas = document.getElementById('particle-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let w, h, particles = [];
  let mouseX = -1000, mouseY = -1000;
  let animId;

  function resize() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
  }

  function createParticles() {
    particles = [];
    const count = Math.floor((w * h) / 10000);
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 2.0,
        vy: (Math.random() - 0.5) * 2.0,
        r: Math.random() * 1.5 + 0.5,
      });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          const alpha = (1 - dist / 120) * 0.08;
          ctx.strokeStyle = `rgba(74,222,128,${alpha})`;
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw particles + mouse interaction
    for (const p of particles) {
      // Mouse repulsion
      const mdx = p.x - mouseX;
      const mdy = p.y - mouseY;
      const mDist = Math.sqrt(mdx * mdx + mdy * mdy);
      if (mDist < 150) {
        const force = (1 - mDist / 150) * 0.8;
        p.vx += (mdx / mDist) * force;
        p.vy += (mdy / mDist) * force;
      }

      // Gentle damping — keep particles moving
      p.vx *= 0.998;
      p.vy *= 0.998;

      // Speed limit
      const speed = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
      if (speed > 4.0) {
        p.vx = (p.vx / speed) * 4.0;
        p.vy = (p.vy / speed) * 4.0;
      }

      p.x += p.vx;
      p.y += p.vy;

      // Wrap
      if (p.x < 0) p.x = w;
      if (p.x > w) p.x = 0;
      if (p.y < 0) p.y = h;
      if (p.y > h) p.y = 0;

      // Draw
      const mouseGlow = mDist < 150 ? (1 - mDist / 150) * 0.5 : 0;
      const alpha = 0.15 + mouseGlow;
      ctx.fillStyle = `rgba(74,222,128,${alpha})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r + mouseGlow * 1.5, 0, Math.PI * 2);
      ctx.fill();
    }

    animId = requestAnimationFrame(draw);
  }

  resize();
  createParticles();
  draw();

  window.addEventListener('resize', () => { resize(); createParticles(); });

  // Track mouse over entire page
  document.addEventListener('mousemove', e => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });
  document.addEventListener('mouseleave', () => {
    mouseX = -1000;
    mouseY = -1000;
  });
}

// ── Scroll-based fade for particle canvas ──
function initScrollFade() {
  const canvas = document.getElementById('particle-canvas');
  if (!canvas) return;
  // Canvas is fixed — keep it visible throughout the page
  // Slightly reduce opacity as user scrolls away from top
  window.addEventListener('scroll', () => {
    const scrollY = window.scrollY;
    const vh = window.innerHeight;
    // Fade from 1.0 at top to 0.6 at 4 viewport heights down — stays visible throughout
    const opacity = Math.max(0.6, 1 - scrollY / (vh * 4));
    canvas.style.opacity = opacity;
  }, { passive: true });
}

// ── Smooth Scroll Offset ──
document.addEventListener('DOMContentLoaded', () => {
  // Hero terminal
  const heroOutput = document.getElementById('terminal-output');
  const heroTypewriter = createTypewriter(heroTerminalLines, heroOutput);
  setTimeout(() => heroTypewriter.start(), 500);

  // Reset button for hero terminal
  const resetBtn = document.getElementById('reset-terminal');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => heroTypewriter.reset());
  }

  // Particle grid background
  initParticleGrid();
  initScrollFade();

  // Smooth scroll with offset for fixed nav
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      const target = document.querySelector(a.getAttribute('href'));
      if (target) {
        e.preventDefault();
        const offset = 80;
        const top = target.getBoundingClientRect().top + window.pageYOffset - offset;
        window.scrollTo({ top, behavior: 'smooth' });
      }
    });
  });

  // Nav scroll effect
  const nav = document.querySelector('.nav');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
      nav.classList.add('scrolled');
    } else {
      nav.classList.remove('scrolled');
    }
  });

  // Counter animation for social proof
  const counters = document.querySelectorAll('.proof-number[data-count]');
  const counterObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        const target = parseInt(el.dataset.count);
        animateCounter(el, target);
        counterObserver.unobserve(el);
      }
    });
  }, { threshold: 0.5 });
  counters.forEach(c => counterObserver.observe(c));

  // Step entrance animations
  const steps = document.querySelectorAll('.step');
  const stepObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('step-visible');
        stepObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.2 });
  steps.forEach(s => stepObserver.observe(s));

  // Scan form
  const form = document.getElementById('scan-form');
  if (form) {
    form.addEventListener('submit', handleScan);
  }
});

function animateCounter(el, target) {
  let current = 0;
  const step = Math.max(1, Math.floor(target / 60));
  const interval = setInterval(() => {
    current += step;
    if (current >= target) {
      current = target;
      clearInterval(interval);
    }
    el.textContent = current.toLocaleString();
  }, 25);
}

async function handleScan(e) {
  e.preventDefault();
  const repo = document.getElementById('repo-url').value;
  const email = document.getElementById('email').value;
  const result = document.getElementById('scan-result');

  result.style.display = 'block';
  result.className = '';
  result.textContent = 'Scanning...';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo_url: repo, email }),
    });
    const data = await res.json();
    if (res.ok) {
      result.className = 'success';
      result.innerHTML = `✓ Scan queued! Check your email for results.`;
    } else {
      result.className = 'error';
      result.textContent = data.error || 'Scan failed. Please try again.';
    }
  } catch (err) {
    result.className = 'error';
    result.textContent = 'Server unavailable. Try again in a moment.';
  }
}
