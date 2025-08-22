// static/theme.js — compact popover theme editor (horizontal) v2
// - Cleans up any old theme UI/banners
// - Button defaults to bottom-left (away from chat send button)
// - Optional anchor: add <span id="theme-anchor"></span> in your header to inline the button there

(function () {
  const LS_KEY = 'nu_theme';
  const root = document.documentElement;

  // --- cleanup any previous/broken theme UIs ---
  ['.th-pop', '.theme-banner', '#theme-editor', '#theme-panel'].forEach(sel => {
    document.querySelectorAll(sel).forEach(n => n.remove());
  });

  // helpers
  const loadTheme = () => {
    try { return JSON.parse(localStorage.getItem(LS_KEY) || '{}'); }
    catch { return {}; }
  };
  const saveTheme = (o) => localStorage.setItem(LS_KEY, JSON.stringify(o));
  const applyVars = (o) => {
    if (!o) return;
    if (o.bg) root.style.setProperty('--bg', o.bg);
    if (o.panel) root.style.setProperty('--panel', o.panel);
    if (o.text) root.style.setProperty('--text', o.text);
    if (o.accent) root.style.setProperty('--accent', o.accent);
  };

  // inject scoped styles
  const style = document.createElement('style');
  style.textContent = `
  :root{
    /* You can override these from your main CSS */
    --theme-btn-bottom: 96px;    /* keep clear of chat input */
    --theme-btn-left: 16px;
    --border: #262a31;
    --panel: var(--panel, #0f1116);
    --text: var(--text, #eaeef2);
    --bg: var(--bg, #0b0c10);
    --accent: var(--accent, #5aa9e6);
  }
  .th-btn {
    padding: 8px 12px; border-radius: 10px;
    border: 1px solid var(--border);
    background: var(--panel); color: var(--text);
    font: 14px/1 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
    cursor: pointer; z-index: 1000;
  }
  /* floating position only if not anchored */
  .th-btn.floating {
    position: fixed; left: var(--theme-btn-left); bottom: var(--theme-btn-bottom);
  }
  .th-pop {
    position: fixed; left: calc(var(--theme-btn-left)); 
    bottom: calc(var(--theme-btn-bottom) + 44px);
    z-index: 1001;
    background: var(--panel); color: var(--text);
    border: 1px solid var(--border); border-radius: 12px;
    padding: 10px; box-shadow: 0 8px 24px rgba(0,0,0,.35);
    display: none; width: max-content; max-width: calc(100vw - 32px);
  }
  .th-pop.show { display: block; }
  .th-row { display: inline-flex; align-items: center; gap: 10px; flex-wrap: nowrap; }
  .th-chip {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 6px 8px; border: 1px solid var(--border);
    border-radius: 10px; white-space: nowrap; background: var(--bg);
  }
  .th-chip label { font-size: 12px; opacity: .9; }
  .th-chip input[type="color"] {
    appearance: none; width: 24px; height: 24px; border: none;
    border-radius: 6px; background: transparent; cursor: pointer; padding: 0;
  }
  .th-actions { display: inline-flex; gap: 8px; margin-left: 8px; }
  .th-actions .btn {
    padding: 6px 10px; border-radius: 10px;
    border: 1px solid var(--border);
    background: var(--bg); color: var(--text);
    cursor: pointer; font-size: 12px;
  }
  .th-close {
    position: absolute; top: 6px; right: 8px; cursor: pointer;
    font-size: 16px; opacity: .7; user-select: none;
  }
  @media (max-width: 520px) {
    .th-row { gap: 6px; }
    .th-chip { padding: 4px 6px; }
    .th-chip label { display:none; }
  }
  `;
  document.head.appendChild(style);

  // build UI
  const anchor = document.getElementById('theme-anchor');
  const btn = document.createElement('button');
  btn.className = 'th-btn' + (anchor ? '' : ' floating');
  btn.type = 'button';
  btn.title = 'Theme';
  btn.textContent = '🎨 Theme';

  const pop = document.createElement('div');
  pop.className = 'th-pop';
  pop.innerHTML = `
    <div class="th-close" title="Close">×</div>
    <div class="th-row">
      <div class="th-chip"><label>Primary</label><input id="th-accent" type="color" value="#5aa9e6"></div>
      <div class="th-chip"><label>Background</label><input id="th-bg" type="color" value="#0b0c10"></div>
      <div class="th-chip"><label>Panel</label><input id="th-panel" type="color" value="#0f1116"></div>
      <div class="th-chip"><label>Text</label><input id="th-text" type="color" value="#eaeef2"></div>
      <div class="th-actions">
        <button class="btn" id="th-apply">Apply</button>
        <button class="btn" id="th-reset">Reset</button>
      </div>
    </div>
  `;

  // attach
  if (anchor) {
    anchor.appendChild(btn);
    // popover near anchor (absolute to viewport)
    const rect = () => anchor.getBoundingClientRect();
    const placeNearAnchor = () => {
      const r = rect();
      pop.style.left = `${Math.max(8, r.left)}px`;
      pop.style.bottom = `${Math.max(60, window.innerHeight - r.bottom + 8)}px`;
    };
    window.addEventListener('resize', () => pop.classList.contains('show') && placeNearAnchor());
    document.body.appendChild(pop);
    btn.addEventListener('click', (e) => { e.stopPropagation(); placeNearAnchor(); pop.classList.toggle('show'); });
  } else {
    // floating mode (bottom-left)
    document.body.appendChild(btn);
    document.body.appendChild(pop);
    btn.addEventListener('click', (e) => { e.stopPropagation(); pop.classList.toggle('show'); });
  }

  // state init
  const theme = loadTheme();
  const setVal = (id, v) => { const el = pop.querySelector(id); if (el && v) el.value = v; };
  setVal('#th-accent', theme.accent);
  setVal('#th-bg', theme.bg);
  setVal('#th-panel', theme.panel);
  setVal('#th-text', theme.text);
  applyVars(theme);

  // events
  const closePop = () => pop.classList.remove('show');
  pop.querySelector('.th-close')?.addEventListener('click', closePop);
  document.addEventListener('keydown', (e) => e.key === 'Escape' && closePop());
  document.addEventListener('click', (e) => {
    if (!pop.classList.contains('show')) return;
    if (!pop.contains(e.target) && e.target !== btn) closePop();
  });

  pop.querySelector('#th-apply')?.addEventListener('click', () => {
    const o = {
      accent: pop.querySelector('#th-accent')?.value || '',
      bg: pop.querySelector('#th-bg')?.value || '',
      panel: pop.querySelector('#th-panel')?.value || '',
      text: pop.querySelector('#th-text')?.value || ''
    };
    saveTheme(o);
    applyVars(o);
    closePop();
  });

  pop.querySelector('#th-reset')?.addEventListener('click', () => {
    localStorage.removeItem(LS_KEY);
    root.style.removeProperty('--bg');
    root.style.removeProperty('--panel');
    root.style.removeProperty('--text');
    root.style.removeProperty('--accent');
    closePop();
  });

  // expose (optional)
  window.__theme = {
    open(){ pop.classList.add('show'); },
    close: closePop,
    get: loadTheme,
    set(o){ saveTheme(o); applyVars(o); }
  };
})();