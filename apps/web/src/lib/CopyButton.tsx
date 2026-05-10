import { useState } from 'react';
import { Check, Copy } from 'lucide-react';

/**
 * Inline copy button — sits next to monospaced IDs / tokens. Falls back to
 * the deprecated execCommand path when the clipboard API isn't available
 * (insecure-context dev setups).
 */
export function CopyButton({ value, title = 'Copy', size = 12 }:
  { value: string; title?: string; size?: number }) {
  const [copied, setCopied] = useState(false);

  const onClick = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1300);
    } catch {
      // ignore — operator can still select-and-copy manually
    }
  };

  return (
    <button
      className="icon-btn copy-btn"
      onClick={onClick}
      title={copied ? 'Copied' : title}
      type="button"
      aria-label={copied ? 'Copied' : 'Copy to clipboard'}
    >
      {copied ? <Check size={size} /> : <Copy size={size} />}
    </button>
  );
}
