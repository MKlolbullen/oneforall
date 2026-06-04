/* Shared chrome (sidebar + topbar) for ReconForge mockup pages. Each
 * preview HTML page calls `renderChrome(activePage, opts)` once after
 * the body's #shell skeleton is in the DOM. The script paints the
 * sidebar groups (pass 3), the topbar workspace selector + user menu
 * (pass 1), and wires up the section collapse toggles so the chrome
 * behaves like the live app even though the page itself is static. */

const SIDEBAR_GROUPS = [
  { id: 'ops', label: 'Operations', pages: [
    ['dashboard',  'Dashboard',       'dashboard-mockup.html'],
    ['workspaces', 'Workspaces',      'workspaces-mockup.html'],
    ['targets',    'Targets',         null],
    ['runs',       'Runs',            'runs-mockup.html'],
    ['results',    'Results',         'results-mockup.html'],
    ['loot',       'Loot',            'loot-mockup.html'],
    ['network',    'Network Graph',   null],
  ]},
  { id: 'builders', label: 'Builders', pages: [
    ['templates', 'Templates',         null],
    ['workflow',  'Workflow Builder',  'workflow-mockup.html'],
    ['tools',     'Tool Catalog',      'tools-mockup.html'],
  ]},
  { id: 'admin', label: 'Admin', pages: [
    ['users',    'Users',     null],
    ['webhooks', 'Webhooks',  null],
    ['scope',    'Scope (ROE)', 'scope-mockup.html'],
  ]},
  { id: 'system', label: 'System', pages: [
    ['audit',    'Audit Log',     null],
    ['settings', 'Settings Pack', null],
  ]},
];

// Icon set — tiny inline SVGs so the mockups don't pull lucide-react in.
// Keys match the page id used in SIDEBAR_GROUPS so renderRow() can look
// each one up by name.
const ICONS = {
  dashboard:  '<rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect>',
  workspaces: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>',
  targets:    '<circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle>',
  runs:       '<polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line>',
  results:    '<circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line>',
  loot:       '<circle cx="12" cy="12" r="8"></circle><path d="M9.5 9h5M9.5 15h5"></path>',
  network:    '<circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>',
  templates:  '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline>',
  workflow:   '<rect x="3" y="3" width="6" height="6"></rect><rect x="15" y="3" width="6" height="6"></rect><rect x="9" y="15" width="6" height="6"></rect><path d="M6 9v3a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V9"></path>',
  tools:      '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path>',
  users:      '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle>',
  webhooks:   '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>',
  scope:      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>',
  audit:      '<path d="M3 3v5h5"></path><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"></path><polyline points="12 7 12 12 15 14"></polyline>',
  settings:   '<circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9z"></path>',
};

function icon(name, size = 16) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${ICONS[name] || ''}</svg>`;
}

function chevron(open) {
  return open
    ? `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>`
    : `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>`;
}

function renderChrome(activePage, opts = {}) {
  const workspace = opts.workspace || 'acme-pentest-q2';
  const runsBadge = opts.runsBadge ?? 3;
  const username  = opts.username  || 'victor';

  const sidebar = SIDEBAR_GROUPS.map((group) => {
    const containsActive = group.pages.some(([id]) => id === activePage);
    const rows = group.pages.map(([id, label, href]) => {
      const isActive = id === activePage;
      const link = href || '#';
      const badge = (id === 'runs' && runsBadge > 0)
        ? `<span class="nav-badge">${runsBadge}</span>` : '';
      return `<a class="nav-row${isActive ? ' active' : ''}" href="${link}">${icon(id, 16)}<span>${label}</span>${badge}</a>`;
    }).join('');
    return `
      <div class="nav-section${containsActive ? '' : ''}">
        <div class="nav-section-header">${chevron(true)}<span>${group.label}</span></div>
        <div class="nav-section-list">${rows}</div>
      </div>
    `;
  }).join('');

  const sidebarEl = document.querySelector('.sidebar');
  if (sidebarEl) {
    sidebarEl.innerHTML = `
      <div class="brand"><span class="brand-mark">RF</span><span>ReconForge</span></div>
      <nav class="nav">${sidebar}</nav>
    `;
  }

  const topbarEl = document.querySelector('.topbar');
  if (topbarEl) {
    topbarEl.innerHTML = `
      <div class="row">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
        <strong class="topbar-brand">Authorized Security Control Plane</strong>
        <label class="workspace-selector">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path></svg>
          <select><option>${workspace}</option><option>All workspaces</option></select>
        </label>
      </div>
      <div class="row">
        <span class="badge passive">dry_run mode</span>
        <span class="badge passive">dry-run safe</span>
        <button class="btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>Search <span class="kbd">⌘K</span></button>
        <button class="btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>Advisor</button>
        <button class="btn" style="padding:3px 6px;"><span class="user-avatar">${username[0].toUpperCase()}</span><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg></button>
      </div>
    `;
  }
}
