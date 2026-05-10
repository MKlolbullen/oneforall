import { type ReactNode } from 'react';
import { Inbox } from 'lucide-react';

/**
 * Drop-in placeholder for empty tables / lists. The CTA is optional — if
 * provided it renders as a button next to the message.
 */
export function EmptyState({ icon, title, body, action }:
  { icon?: ReactNode; title: string; body?: string; action?: ReactNode }) {
  return (
    <div className="empty-state" role="status">
      <div className="empty-state-icon">{icon ?? <Inbox size={28} />}</div>
      <div className="empty-state-text">
        <strong>{title}</strong>
        {body && <span className="muted">{body}</span>}
      </div>
      {action && <div className="empty-state-action">{action}</div>}
    </div>
  );
}
