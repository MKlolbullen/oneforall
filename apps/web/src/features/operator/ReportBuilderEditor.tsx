import { useState } from "react";
import type { EvidenceItem, ReportDraft, ReportSection } from "./types";

export function ReportBuilderEditor({
  reports,
  evidence,
  onSave,
  onExport,
}: {
  reports: ReportDraft[];
  evidence: EvidenceItem[];
  onSave: (draft: ReportDraft) => Promise<ReportDraft>;
  onExport: (id: string, format: "md" | "html" | "pdf" | "json") => Promise<{ url: string }>;
}) {
  const [draft, setDraft] = useState<ReportDraft | undefined>(reports[0]);
  const [saving, setSaving] = useState(false);

  if (!draft) return <section className="occ-card">No report drafts available.</section>;

  function updateSection(id: string, patch: Partial<ReportSection>) {
    setDraft({ ...draft, sections: draft.sections.map((s) => s.id === id ? { ...s, ...patch } : s) });
  }

  async function save() {
    setSaving(true);
    try {
      setDraft(await onSave(draft));
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="occ-grid-2">
      <div className="occ-card">
        <h2>Report Builder / Editor</h2>
        <input value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} />
        <p>Target: {draft.target}</p>
        <div className="occ-row wrap">
          <button onClick={() => void save()}>{saving ? "Saving..." : "Save"}</button>
          {(["md", "html", "pdf", "json"] as const).map((fmt) => (
            <button key={fmt} onClick={() => void onExport(draft.id, fmt)}>Export {fmt}</button>
          ))}
        </div>
        {draft.sections.map((s) => (
          <div key={s.id} className="occ-editor-section">
            <input value={s.title} onChange={(e) => updateSection(s.id, { title: e.target.value })} />
            <textarea value={s.body} onChange={(e) => updateSection(s.id, { body: e.target.value })} />
            <small>{s.evidenceIds.length} evidence item(s)</small>
          </div>
        ))}
      </div>
      <div className="occ-card">
        <h3>Available evidence</h3>
        {evidence.map((e) => (
          <div key={e.id} className="occ-list-row">
            <strong>{e.title}</strong>
            <span>{e.type}</span>
            <p>{e.preview}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
