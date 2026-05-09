/**
 * Theme switching.
 *
 * The default look is the original cyan/teal dark theme.
 * "pd-cloud" is a tighter ProjectDiscovery-cloud-inspired palette: warmer black
 * background, sharper card borders, pink+cyan dual accent, JetBrains-Mono code.
 *
 * Both themes are dark — this is not a light-mode toggle, just two dark
 * dialects. We persist the choice in localStorage so reloads honor it.
 */
export type Theme = 'classic' | 'pd-cloud';

const KEY = 'reconforge.theme';

export function loadTheme(): Theme {
  if (typeof window === 'undefined') return 'classic';
  const stored = window.localStorage.getItem(KEY);
  return stored === 'pd-cloud' ? 'pd-cloud' : 'classic';
}

export function applyTheme(theme: Theme): void {
  if (typeof document === 'undefined') return;
  if (theme === 'classic') {
    document.documentElement.removeAttribute('data-theme');
  } else {
    document.documentElement.setAttribute('data-theme', theme);
  }
}

export function persistTheme(theme: Theme): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(KEY, theme);
}

export const THEMES: { id: Theme; label: string; description: string }[] = [
  { id: 'classic', label: 'Classic', description: 'Cyan / teal dark theme — the original look.' },
  { id: 'pd-cloud', label: 'PD Cloud', description: 'ProjectDiscovery-cloud-inspired: pink+cyan, sharper borders, mono code.' },
];
