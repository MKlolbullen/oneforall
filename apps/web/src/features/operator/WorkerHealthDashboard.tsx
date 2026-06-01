import type { WorkerHealth } from "./types";

export function WorkerHealthDashboard({ workers }: { workers: WorkerHealth[] }) {
  const activeRuns = workers.reduce((sum, w) => sum + w.activeRuns, 0);
  const queueDepth = workers.reduce((sum, w) => sum + w.queueDepth, 0);

  return (
    <section className="occ-stack">
      <div className="occ-card">
        <h2>Worker Health</h2>
        <p>Runner health is operational truth. If workers are degraded, findings and reports are suspect.</p>
        <div className="occ-metrics big">
          <span>{workers.length} workers</span>
          <span>{activeRuns} active runs</span>
          <span>{queueDepth} queued jobs</span>
        </div>
      </div>
      <div className="occ-grid">
        {workers.map((w) => (
          <article key={w.id} className="occ-card">
            <div className="occ-card-title">
              <h3>{w.hostname}</h3>
              <span className={`occ-pill ${w.status}`}>{w.status}</span>
            </div>
            <div className="occ-metrics vertical">
              <span>Queue: {w.queueDepth}</span>
              <span>Active: {w.activeRuns}</span>
              <span>Heartbeat: {w.lastHeartbeatSeconds}s ago</span>
              <span>Tools: {w.toolsAvailable} ok / {w.toolsMissing} missing</span>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
