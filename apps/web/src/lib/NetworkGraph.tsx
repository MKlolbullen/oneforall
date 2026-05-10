import { useEffect, useMemo, useState } from 'react';
import { Background, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow } from '@xyflow/react';
import { Crosshair, Globe, Link2, RefreshCw, Server, ShieldAlert } from 'lucide-react';
import { api } from './api';
import type { GraphEdge, GraphNode, GraphPayload, Workspace } from '../types';

// Concentric layout: targets in the centre, then domains, urls, ips, findings.
// We don't try to honour real geometry — degree drives the radius and
// alphabetical order anchors the angle, which keeps re-renders stable.
const RING_ORDER: Record<string, number> = {
  target: 0,
  domain: 1,
  url: 2,
  ip: 3,
  finding: 4,
};
const RING_RADIUS = [0, 220, 420, 580, 760];
const FALLBACK_RADIUS = 920;

const KIND_COLORS: Record<string, string> = {
  target: '#22d3ee',
  domain: '#a78bfa',
  url: '#34d399',
  ip: '#f59e0b',
  finding: '#f472b6',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#64748b',
};

function nodeIcon(kind: string) {
  switch (kind) {
    case 'target': return <Crosshair size={14} />;
    case 'domain': return <Globe size={14} />;
    case 'url': return <Link2 size={14} />;
    case 'ip': return <Server size={14} />;
    case 'finding': return <ShieldAlert size={14} />;
    default: return null;
  }
}

function GraphNodeCard({ data }: { data: { node: GraphNode } }) {
  const { node } = data;
  const ring = KIND_COLORS[node.kind] ?? '#64748b';
  const sev = node.kind === 'finding' && node.severity ? SEVERITY_COLORS[node.severity.toLowerCase()] : null;
  const scale = 1 + Math.min(0.8, node.centrality * 4);  // centrality is 0..1, mostly tiny
  return (
    <div
      className="graph-node"
      style={{ borderColor: sev ?? ring, transform: `scale(${scale})` }}
      title={`${node.kind} · centrality ${node.centrality.toFixed(3)}${node.severity ? ` · ${node.severity}` : ''}`}
    >
      <Handle type="target" position={Position.Left} style={{ background: ring }} />
      <div className="graph-node-row">
        <span className="graph-node-icon" style={{ color: ring }}>{nodeIcon(node.kind)}</span>
        <strong>{node.label}</strong>
      </div>
      <div className="graph-node-meta">
        <span>{node.kind}</span>
        {node.severity && <span className="graph-node-sev" style={{ color: sev ?? '#94a3b8' }}>{node.severity}</span>}
      </div>
      <Handle type="source" position={Position.Right} style={{ background: ring }} />
    </div>
  );
}

const NODE_TYPES = { rfNetwork: GraphNodeCard };

type LayoutNode = {
  id: string;
  type: 'rfNetwork';
  position: { x: number; y: number };
  data: { node: GraphNode };
};

type LayoutEdge = {
  id: string;
  source: string;
  target: string;
  label?: string;
  animated?: boolean;
  markerEnd: { type: MarkerType };
  style?: Record<string, unknown>;
};

function layoutGraph(payload: GraphPayload): { nodes: LayoutNode[]; edges: LayoutEdge[] } {
  const groups: Record<string, GraphNode[]> = {};
  for (const node of payload.nodes) {
    (groups[node.kind] ??= []).push(node);
  }
  for (const arr of Object.values(groups)) {
    arr.sort((a, b) => b.centrality - a.centrality || a.label.localeCompare(b.label));
  }

  const nodes: LayoutNode[] = [];
  for (const [kind, list] of Object.entries(groups)) {
    const ring = RING_ORDER[kind] ?? 5;
    const radius = RING_RADIUS[ring] ?? FALLBACK_RADIUS;
    const count = list.length;
    list.forEach((n, i) => {
      const angle = count === 1 ? 0 : (i / count) * Math.PI * 2;
      const position = radius === 0
        ? { x: 0, y: 0 }
        : { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius };
      nodes.push({ id: n.id, type: 'rfNetwork', position, data: { node: n } });
    });
  }

  const edges: LayoutEdge[] = payload.edges.map((e: GraphEdge, i) => ({
    id: `${i}:${e.source}->${e.target}`,
    source: e.source,
    target: e.target,
    label: e.kind,
    animated: e.kind === 'finds',
    markerEnd: { type: MarkerType.ArrowClosed },
    style: { stroke: e.kind === 'finds' ? '#f472b6' : '#475569', strokeWidth: 1.2 },
  }));

  return { nodes, edges };
}

export function NetworkGraph() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [workspaceId, setWorkspaceId] = useState<string>('');
  const [maxNodes, setMaxNodes] = useState(600);
  const [payload, setPayload] = useState<GraphPayload | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.workspaces()
      .then((rows) => {
        setWorkspaces(rows);
        if (!workspaceId && rows[0]) setWorkspaceId(rows[0].id);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    // workspaceId intentionally omitted — we only auto-pick once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const reload = async (wsId: string, limit: number) => {
    if (!wsId) return;
    setLoading(true); setError(null);
    try {
      setPayload(await api.workspaceGraph(wsId, limit));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (workspaceId) reload(workspaceId, maxNodes).catch(console.error);
  }, [workspaceId, maxNodes]);

  const layout = useMemo(() => payload ? layoutGraph(payload) : { nodes: [], edges: [] }, [payload]);
  const stats = payload?.stats ?? {};
  const byKind = (stats.by_kind ?? {}) as Record<string, number>;

  return (
    <div className="grid">
      <div className="card">
        <div className="row space">
          <h3>Network graph</h3>
          <button className="btn small" onClick={() => reload(workspaceId, maxNodes)} disabled={loading}>
            <RefreshCw size={14} /> {loading ? 'Loading...' : 'Reload'}
          </button>
        </div>
        <p className="muted">
          Targets, domains, URLs, IPs and findings linked by the runner. Node size scales with
          betweenness centrality so pivot points stand out.
        </p>
        <div className="toolbar">
          <select className="input" value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)}>
            {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
          </select>
          <select className="input" value={maxNodes} onChange={(e) => setMaxNodes(Number(e.target.value))}>
            {[100, 300, 600, 1000, 2000].map((n) => <option key={n} value={n}>{n} max nodes</option>)}
          </select>
          <span className="muted">
            {stats.node_count ?? 0} nodes · {stats.edge_count ?? 0} edges
            {payload?.truncated && <span className="badge bad" style={{ marginLeft: 8 }}>truncated</span>}
          </span>
        </div>
        <div className="graph-legend">
          {Object.entries(KIND_COLORS).map(([kind, color]) => (
            <span key={kind} className="graph-legend-item">
              <span className="graph-legend-dot" style={{ background: color }} />
              {kind} ({byKind[kind] ?? 0})
            </span>
          ))}
        </div>
      </div>
      {error && <div className="card"><p className="advice-error">{error}</p></div>}
      <div className="card flow-pane network-graph-pane">
        <ReactFlow
          nodes={layout.nodes}
          edges={layout.edges}
          nodeTypes={NODE_TYPES}
          fitView
          minZoom={0.1}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
        >
          <Background />
          <MiniMap pannable zoomable />
          <Controls />
        </ReactFlow>
      </div>
    </div>
  );
}
