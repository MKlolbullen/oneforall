import { useState } from "react";
import type { EvidenceItem, ReportDraft } from "./types";

export function EvidenceToReportMapper({
  evidence,
  reports,
  onMap,
}: {
  evidence: EvidenceItem[];
  reports: ReportDraft[];
  onMap: (evidenceId: string, sectionId: string) => Promise<unknown>;
}) {
  const [reportId, setReportId] = useState(reports[0]?.id || "");
  const report = reports.find((r) => r.id === reportId) || reports[0];
  const [sectionId, setSectionId] = useState(report?.sections[0]?.id || "");

  if (!report) return <section className="occ-card">No report draft available.</section>;

  return (
    <section className="occ-grid-2">
      <div className="occ-card">
        <h2>Evidence-to-Report Mapping</h2>
        <p>Attach findings, screenshots, HTTP exchanges, artifacts, and loot directly to report sections.</p>
        <select value={report.id} onChange={(e) => setReportId(e.target.value)}>
          {reports.map((r) => <option key={r.id} value={r.id}>{r.title}</option>)}
        </select>
        <select value={sectionId} onChange={(e) => setSectionId(e.target.value)}>
          {report.sections.map((s) => <option key={s.id} value={s.id}>{s.title}</option>)}
        </select>
      </div>
      <div className="occ-card">
        <h3>Evidence</h3>
        {evidence.map((e) => (
          <article key={e.id} className="occ-list-row">
            <strong>{e.title}</strong>
            <span>{e.type} · {e.source}</span>
            <p>{e.preview}</p>
            <button onClick={() => void onMap(e.id, sectionId)}>Map to section</button>
          </article>
        ))}
      </div>
    </section>
  );
}
