import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent } from 'react';
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  addEdge,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Connection,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react';
import { Boxes, Cloud, CloudUpload, Crosshair, FilePlus2, FolderOpen, Rocket, Save, Search, Settings2, Trash2, X } from 'lucide-react';
import { api } from './api';
import { EmptyState } from './EmptyState';
import { useConfirm } from './Confirm';
import { useNav } from './nav';
import { useToast } from './Toast';
import type { AdHocStep, Profile, SavedWorkflow, Target, Tool, Workspace } from '../types';

/* ============================================================================
 * Types + helpers
 * ========================================================================== */

type TargetNodeData = { kind: 'target'; label: string; targetId: string | null };

type ToolNodeData = {
  kind: 'tool';
  toolId: string;
  tool: Tool;
  argv_replace?: string[];
  argv_extra?: string[];
  timeout_seconds?: number;
  max_retries?: number;
  retry_backoff_seconds?: number;
  continue_on_error?: boolean;
};

type WfNodeData = TargetNodeData | ToolNodeData;
type WfNode = Node<WfNodeData>;

// Fixed palette for the common ProjectDiscovery artifact types; anything not
// in the map gets a stable hashed HSL so new types still render distinctively.
const TYPE_COLORS: Record<string, string> = {
  domain: '#22d3ee',
  domain_list: '#22d3ee',
  url: '#ec4899',
  url_list: '#ec4899',
  ip: '#f59e0b',
  ip_list: '#f59e0b',
  cidr: '#f59e0b',
  asn: '#a78bfa',
  port_list: '#fbbf24',
  jsonl: '#84cc16',
  text: '#94a3b8',
  file: '#84cc16',
  target_string: '#22d3ee',
};

function typeColor(t: string): string {
  if (TYPE_COLORS[t]) return TYPE_COLORS[t];
  // Stable hash → HSL. Same string always renders the same color so the
  // operator can scan a complex graph at a glance.
  let h = 0;
  for (let i = 0; i < t.length; i++) h = (h * 31 + t.charCodeAt(i)) >>> 0;
  return `hsl(${h % 360}, 65%, 60%)`;
}

/** Connection compatibility — exact match, or singular→list, or target→domain/url. */
function compatibleTypes(sourceType: string, targetType: string): boolean {
  if (sourceType === targetType) return true;
  if (`${sourceType}_list` === targetType) return true;
  if (sourceType === 'target_string' && ['domain', 'url', 'target'].includes(targetType)) return true;
  return false;
}

let __nodeCounter = 1;
function newNodeId(prefix: string): string {
  __nodeCounter += 1;
  return `${prefix}_${Date.now().toString(36)}_${__nodeCounter}`;
}

/** Kahn's topological sort. Returns `null` if a cycle is detected. */
function topoSort(nodes: WfNode[], edges: Edge[]): WfNode[] | null {
  const indeg: Record<string, number> = {};
  const adj: Record<string, string[]> = {};
  for (const n of nodes) { indeg[n.id] = 0; adj[n.id] = []; }
  for (const e of edges) {
    if (!(e.source in indeg) || !(e.target in indeg)) continue;
    indeg[e.target] = (indeg[e.target] ?? 0) + 1;
    (adj[e.source] = adj[e.source] ?? []).push(e.target);
  }
  const ready = nodes.filter((n) => indeg[n.id] === 0).map((n) => n.id);
  const order: string[] = [];
  while (ready.length) {
    const id = ready.shift()!;
    order.push(id);
    for (const next of adj[id] ?? []) {
      indeg[next] -= 1;
      if (indeg[next] === 0) ready.push(next);
    }
  }
  if (order.length !== nodes.length) return null; // cycle
  const byId: Record<string, WfNode> = Object.fromEntries(nodes.map((n) => [n.id, n]));
  return order.map((id) => byId[id]);
}

const STORAGE_KEY = 'reconforge:workflow-builder:v1';

type LocalSavedWorkflow = {
  name: string;
  workspaceId: string | null;
  targetId: string | null;
  nodes: WfNode[];
  edges: Edge[];
  savedAt: string;
};

function loadSavedWorkflows(): Record<string, LocalSavedWorkflow> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Record<string, LocalSavedWorkflow>) : {};
  } catch { return {}; }
}

function persistSavedWorkflows(workflows: Record<string, LocalSavedWorkflow>): void {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(workflows)); }
  catch { /* quota — best-effort */ }
}

/** Stripped-for-persistence node — drop the live Tool object so the saved
 *  blob doesn't carry stale registry data. Toolbar re-hydrates on load. */
function stripNodeForPersistence(n: WfNode): WfNode {
  if (n.data.kind === 'tool') {
    return {
      ...n,
      data: {
        kind: 'tool',
        toolId: n.data.toolId,
        tool: { id: n.data.toolId, name: n.data.toolId, category: '', description: '', risk: 'passive', requires_authorization: false },
        argv_replace: n.data.argv_replace,
        argv_extra: n.data.argv_extra,
        timeout_seconds: n.data.timeout_seconds,
        max_retries: n.data.max_retries,
        retry_backoff_seconds: n.data.retry_backoff_seconds,
        continue_on_error: n.data.continue_on_error,
      },
    };
  }
  // Drop the live target id — that's a launch-time choice, not a property
  // of the workflow shape.
  return { ...n, data: { kind: 'target', label: 'Target', targetId: null } };
}

/** Build the steps[] in topo order from the live nodes/edges. */
function buildSteps(nodes: WfNode[], edges: Edge[]): AdHocStep[] {
  const sorted = topoSort(nodes, edges) ?? nodes;
  return sorted
    .filter((n): n is WfNode & { data: ToolNodeData } => n.data.kind === 'tool')
    .map((n) => {
      const d = n.data;
      const step: AdHocStep = { tool: d.toolId };
      if (d.argv_replace && d.argv_replace.length) step.argv_replace = d.argv_replace;
      if (d.argv_extra && d.argv_extra.length) step.argv_extra = d.argv_extra;
      if (d.timeout_seconds != null) step.timeout_seconds = d.timeout_seconds;
      if (d.max_retries != null) step.max_retries = d.max_retries;
      if (d.retry_backoff_seconds != null) step.retry_backoff_seconds = d.retry_backoff_seconds;
      if (d.continue_on_error != null) step.continue_on_error = d.continue_on_error;
      return step;
    });
}

/* ============================================================================
 * Public component
 * ========================================================================== */

export function WorkflowBuilder() {
  // ReactFlowProvider is required so useReactFlow() works for the drop handler.
  return (
    <ReactFlowProvider>
      <WorkflowBuilderInner />
    </ReactFlowProvider>
  );
}

function WorkflowBuilderInner() {
  const toast = useToast();
  const confirm = useConfirm();
  const { navigate, consume } = useNav();
  const reactFlow = useReactFlow();

  const [tools, setTools] = useState<Tool[]>([]);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);

  const [name, setName] = useState('My workflow');
  const [description, setDescription] = useState('');
  const [workspaceId, setWorkspaceId] = useState<string | null>(null);
  const [targetId, setTargetId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showLoadMenu, setShowLoadMenu] = useState(false);
  // Cloud-side persistence — null until the user saves or loads from server.
  const [currentWorkflowId, setCurrentWorkflowId] = useState<string | null>(null);
  const [cloudList, setCloudList] = useState<SavedWorkflow[]>([]);
  const [showCloudMenu, setShowCloudMenu] = useState(false);

  const [nodes, setNodes, onNodesChange] = useNodesState<WfNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const canvasWrapperRef = useRef<HTMLDivElement | null>(null);

  // Seed the canvas from a YAML profile — used by Templates' "Customize"
  // CTA. Layout is a horizontal chain: target → step 1 → step 2 → … →
  // step N, so the operator can branch / override / reorder without
  // staring at a blank canvas.
  const seedFromProfile = useCallback((profile: Profile, registryById: Record<string, Tool>) => {
    const seeded: WfNode[] = [{
      id: 'target-1', type: 'targetNode', position: { x: 40, y: 200 },
      data: { kind: 'target', label: 'Target', targetId: null }, deletable: false,
    }];
    const seededEdges: Edge[] = [];
    let prevId: string = 'target-1';
    profile.steps.forEach((step, i) => {
      const tool = registryById[step.tool];
      if (!tool) return; // skip unknown tools rather than poisoning the canvas
      const id = newNodeId(step.tool);
      seeded.push({
        id, type: 'toolNode',
        position: { x: 40 + 260 * (i + 1), y: 200 },
        data: { kind: 'tool', toolId: step.tool, tool },
      });
      // Connect prev → this node on best-effort matching handles. Use
      // first output of source and first input of target; if the canvas
      // user later wants different sockets they can drag a new edge.
      const prevNode = seeded.find((n) => n.id === prevId);
      const sourceHandle = prevNode?.data.kind === 'tool'
        ? `out:${prevNode.data.tool.outputs?.[0]?.name ?? 'out'}`
        : 'out:target';
      const targetHandle = `in:${tool.inputs?.[0]?.name ?? 'target'}`;
      seededEdges.push({
        id: `e_${prevId}_${id}`,
        source: prevId, sourceHandle,
        target: id, targetHandle,
      });
      prevId = id;
    });
    setNodes(seeded);
    setEdges(seededEdges);
    setName(`${profile.name} (custom)`);
    setDescription(profile.description ?? '');
    setCurrentWorkflowId(null);  // forked copy is fresh, not server-backed
    setSelectedId(null);
  }, [setNodes, setEdges]);

  // ---- Initial load ---------------------------------------------------------
  useEffect(() => {
    const params = consume();
    // Tools needed both for the palette AND for seeding from a profile, so
    // wait on the fetch in the fromProfile path.
    const toolsPromise = api.tools();
    toolsPromise.then(setTools).catch((e) => toast.fromError(e, 'Failed to load tools'));
    api.workspaces().then((ws) => {
      setWorkspaces(ws);
      if (ws[0] && !params.workflowId) setWorkspaceId(ws[0].id);
    }).catch(() => { /* empty workspace list is OK */ });
    api.targets().then(setTargets).catch(() => { /* same */ });

    if (params.workflowId) {
      // Deeplinked from Templates / Workspaces: fetch + hydrate. Tools fetch
      // races with this; the second useEffect (on toolsById) rebinds the
      // tool objects to the freshly-loaded registry, so a slow tools fetch
      // doesn't strand the node renderer.
      api.workflow(params.workflowId)
        .then(hydrateFromServer)
        .catch((e) => toast.fromError(e, 'Failed to load workflow'));
    } else if (params.fromProfile) {
      // "Customize" path: fetch the profile + tools in parallel; seed the
      // canvas once both arrive.
      Promise.all([api.profiles(), toolsPromise])
        .then(([allProfiles, allTools]) => {
          const profile = allProfiles.find((p) => p.id === params.fromProfile);
          if (!profile) {
            toast.warn('Profile not found', `Could not seed canvas from ${params.fromProfile}.`);
            return;
          }
          const byId = Object.fromEntries(allTools.map((t) => [t.id, t]));
          seedFromProfile(profile, byId);
        })
        .catch((e) => toast.fromError(e, 'Failed to seed from profile'));
    } else {
      // Seed canvas with a target node so the user has a connection anchor.
      setNodes([{
        id: 'target-1', type: 'targetNode', position: { x: 40, y: 200 },
        data: { kind: 'target', label: 'Target', targetId: null }, deletable: false,
      }]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep the target node's data in sync with the selected target so its label
  // reflects the actual host.
  useEffect(() => {
    const t = targets.find((x) => x.id === targetId);
    setNodes((prev) => prev.map((n) =>
      n.data.kind === 'target'
        ? { ...n, data: { ...n.data, targetId, label: t ? t.value : 'Target' } }
        : n,
    ));
  }, [targetId, targets, setNodes]);

  // Workspace switch trims targets that no longer belong to the workspace.
  const workspaceTargets = useMemo(
    () => targets.filter((t) => !workspaceId || t.workspace_id === workspaceId),
    [targets, workspaceId],
  );

  const toolsById = useMemo<Record<string, Tool>>(
    () => Object.fromEntries(tools.map((t) => [t.id, t])),
    [tools],
  );

  // Re-bind tool objects on the canvas when the registry finishes loading
  // (deeplink path can race tools().then). Keeps node renderers showing the
  // up-to-date input/output handles even if a workflow loaded before the
  // tools list arrived.
  useEffect(() => {
    if (Object.keys(toolsById).length === 0) return;
    setNodes((prev) => prev.map((n) => {
      if (n.data.kind === 'tool' && (!n.data.tool || !n.data.tool.inputs)) {
        const tool = toolsById[n.data.toolId];
        if (tool) return { ...n, data: { ...n.data, tool } };
      }
      return n;
    }));
  }, [toolsById, setNodes]);

  // ---- Drag from palette ----------------------------------------------------
  const onDragOver = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const toolId = e.dataTransfer.getData('application/reactflow-tool');
    if (!toolId) return;
    const tool = toolsById[toolId];
    if (!tool) return;
    const position = reactFlow.screenToFlowPosition({ x: e.clientX, y: e.clientY });
    const id = newNodeId(toolId);
    const node: WfNode = {
      id,
      type: 'toolNode',
      position,
      data: { kind: 'tool', toolId, tool },
    };
    setNodes((prev) => [...prev, node]);
    setSelectedId(id);
  }, [reactFlow, setNodes, toolsById]);

  const addToolAtCenter = useCallback((tool: Tool) => {
    // Click-to-add fallback for users who can't drag (touch screens, a11y).
    const bounds = canvasWrapperRef.current?.getBoundingClientRect();
    const position = reactFlow.screenToFlowPosition({
      x: (bounds?.left ?? 0) + (bounds?.width ?? 600) / 2,
      y: (bounds?.top ?? 0) + (bounds?.height ?? 400) / 2,
    });
    const id = newNodeId(tool.id);
    setNodes((prev) => [...prev, {
      id, type: 'toolNode', position,
      data: { kind: 'tool', toolId: tool.id, tool },
    }]);
    setSelectedId(id);
  }, [reactFlow, setNodes]);

  // ---- Connect with type-compatibility check -------------------------------
  const onConnect = useCallback((conn: Connection) => {
    const src = nodes.find((n) => n.id === conn.source);
    const dst = nodes.find((n) => n.id === conn.target);
    if (!src || !dst) return;
    const srcType = handleType(src, conn.sourceHandle, 'out');
    const dstType = handleType(dst, conn.targetHandle, 'in');
    if (srcType && dstType && !compatibleTypes(srcType, dstType)) {
      toast.warn(
        'Type mismatch — edge skipped',
        `${srcType} → ${dstType}. Connect a compatible socket, or override argv on the consumer instead.`,
      );
      return;
    }
    setEdges((prev) => addEdge({
      ...conn,
      markerEnd: { type: MarkerType.ArrowClosed, color: srcType ? typeColor(srcType) : '#22d3ee' },
      style: { stroke: srcType ? typeColor(srcType) : '#22d3ee', strokeWidth: 2 },
      data: { type: srcType },
    }, prev));
  }, [nodes, setEdges, toast]);

  // ---- Inspector edits -----------------------------------------------------
  const selected = nodes.find((n) => n.id === selectedId) ?? null;

  const updateSelectedTool = useCallback((updater: (data: ToolNodeData) => ToolNodeData) => {
    setNodes((prev) => prev.map((n) =>
      n.id === selectedId && n.data.kind === 'tool'
        ? { ...n, data: updater(n.data) }
        : n,
    ));
  }, [selectedId, setNodes]);

  const deleteSelected = useCallback(() => {
    if (!selectedId) return;
    setNodes((prev) => prev.filter((n) => n.id !== selectedId || n.data.kind === 'target'));
    setEdges((prev) => prev.filter((e) => e.source !== selectedId && e.target !== selectedId));
    setSelectedId(null);
  }, [selectedId, setNodes, setEdges]);

  // ---- Save / load to localStorage -----------------------------------------
  const saveCurrent = useCallback(() => {
    if (!name.trim()) {
      toast.warn('Name required', 'Give your workflow a name before saving.');
      return;
    }
    const all = loadSavedWorkflows();
    all[name] = {
      name, workspaceId, targetId,
      nodes, edges,
      savedAt: new Date().toISOString(),
    };
    persistSavedWorkflows(all);
    toast.success('Workflow saved', `Stored "${name}" in this browser.`);
  }, [name, workspaceId, targetId, nodes, edges, toast]);

  const loadWorkflow = useCallback((wf: LocalSavedWorkflow) => {
    // Rehydrate `tool` on each ToolNodeData from the live registry so the
    // node knows its current input/output types even if the saved copy is
    // stale relative to a registry change.
    const hydrated: WfNode[] = wf.nodes.map((n) => {
      if (n.data.kind === 'tool') {
        const tool = toolsById[n.data.toolId];
        if (!tool) return n; // dangling tool reference; render what we have
        return { ...n, data: { ...n.data, tool } };
      }
      return n;
    });
    setNodes(hydrated);
    setEdges(wf.edges);
    setName(wf.name);
    setCurrentWorkflowId(null);  // local copies aren't server-backed
    if (wf.workspaceId) setWorkspaceId(wf.workspaceId);
    if (wf.targetId) setTargetId(wf.targetId);
    setSelectedId(null);
    setShowLoadMenu(false);
    toast.info('Workflow loaded (local)', wf.name);
  }, [toolsById, setNodes, setEdges, toast]);

  // Hydrate a server-backed workflow into the canvas. Toolbar Tool references
  // are re-attached from the live registry so a tool whose IO definition
  // changed since the workflow was saved renders the current shape.
  const hydrateFromServer = useCallback((wf: SavedWorkflow) => {
    const graph = (wf.body?.graph as { nodes?: WfNode[]; edges?: Edge[] } | undefined) ?? {};
    const rawNodes: WfNode[] = graph.nodes ?? [];
    const rawEdges: Edge[] = graph.edges ?? [];
    const hydrated: WfNode[] = rawNodes.length > 0 ? rawNodes.map((n) => {
      if (n.data?.kind === 'tool') {
        const tool = toolsById[n.data.toolId];
        return tool ? { ...n, data: { ...n.data, tool } } : n;
      }
      return n;
    }) : [{
      id: 'target-1', type: 'targetNode', position: { x: 40, y: 200 },
      data: { kind: 'target', label: 'Target', targetId: null }, deletable: false,
    }];
    setNodes(hydrated);
    setEdges(rawEdges);
    setName(wf.name);
    setDescription(wf.description ?? '');
    setWorkspaceId(wf.workspace_id);
    setCurrentWorkflowId(wf.id);
    setSelectedId(null);
    setShowCloudMenu(false);
  }, [toolsById, setNodes, setEdges]);

  const newWorkflow = useCallback(() => {
    setNodes([{
      id: 'target-1', type: 'targetNode', position: { x: 40, y: 200 },
      data: { kind: 'target', label: 'Target', targetId: targetId },
      deletable: false,
    }]);
    setEdges([]);
    setName('New workflow');
    setDescription('');
    setCurrentWorkflowId(null);
    setSelectedId(null);
  }, [setNodes, setEdges, targetId]);

  // ---- Server-side save / load / delete ------------------------------------
  const refreshCloudList = useCallback(() => {
    if (!workspaceId) return;
    api.workflows(workspaceId).then(setCloudList).catch(() => { /* dropdown ok empty */ });
  }, [workspaceId]);

  useEffect(() => { refreshCloudList(); }, [refreshCloudList]);

  const cloudSave = useCallback(async (asNew = false) => {
    if (!workspaceId) {
      toast.warn('Pick a workspace', 'Save needs a workspace context.');
      return;
    }
    if (!name.trim()) {
      toast.warn('Name required', 'Give your workflow a name before saving.');
      return;
    }
    if (nodes.filter((n) => n.data.kind === 'tool').length === 0) {
      toast.warn('Empty workflow', 'Drag at least one tool onto the canvas first.');
      return;
    }
    if (!topoSort(nodes, edges)) {
      toast.warn('Cycle detected', 'A workflow must be acyclic.');
      return;
    }
    setBusy(true);
    try {
      const body = {
        steps: buildSteps(nodes, edges),
        graph: {
          nodes: nodes.map(stripNodeForPersistence),
          edges: edges,
        },
      };
      let saved: SavedWorkflow;
      if (currentWorkflowId && !asNew) {
        saved = await api.updateWorkflow(currentWorkflowId, {
          name, description: description || null, body,
        });
        toast.success('Workflow saved', `Updated "${saved.name}".`);
      } else {
        saved = await api.createWorkflow({
          workspace_id: workspaceId,
          name, description: description || null, body,
        });
        setCurrentWorkflowId(saved.id);
        toast.success('Workflow saved', `Created "${saved.name}".`);
      }
      refreshCloudList();
    } catch (e) {
      toast.fromError(e, 'Save failed');
    } finally {
      setBusy(false);
    }
  }, [workspaceId, name, description, nodes, edges, currentWorkflowId, refreshCloudList, toast]);

  const cloudDelete = useCallback(async () => {
    if (!currentWorkflowId) return;
    const ok = await confirm({
      title: `Delete "${name}"?`,
      body: 'This removes the saved workflow from the workspace for every operator. Local browser copies remain.',
      confirmLabel: 'Delete',
      cancelLabel: 'Keep',
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.deleteWorkflow(currentWorkflowId);
      toast.success('Workflow deleted');
      setCurrentWorkflowId(null);
      refreshCloudList();
    } catch (e) {
      toast.fromError(e, 'Delete failed');
    }
  }, [currentWorkflowId, name, confirm, refreshCloudList, toast]);

  // ---- Launch ---------------------------------------------------------------
  const launch = useCallback(async () => {
    if (!workspaceId || !targetId) {
      toast.warn('Pick a target', 'A workspace and target are required to launch.');
      return;
    }
    const toolNodes = nodes.filter((n) => n.data.kind === 'tool');
    if (toolNodes.length === 0) {
      toast.warn('Empty workflow', 'Drag at least one tool onto the canvas.');
      return;
    }
    if (!topoSort(nodes, edges)) {
      toast.warn('Cycle detected', 'A workflow must be acyclic. Remove the loop and try again.');
      return;
    }
    const steps = buildSteps(nodes, edges);
    setBusy(true);
    try {
      // If editing a server-backed workflow with no pending changes, use
      // the dedicated launch route so the run records workflow_id; otherwise
      // post as ad-hoc (the canvas may diverge from the saved blob).
      const run = currentWorkflowId
        ? await api.launchWorkflow(currentWorkflowId, { target_id: targetId })
        : await api.createAdhocRun({
            workspace_id: workspaceId,
            target_id: targetId,
            name,
            steps,
          });
      toast.success('Run queued', `${steps.length} step${steps.length === 1 ? '' : 's'} — opening Runs.`);
      navigate('runs', { runId: run.id });
    } catch (e) {
      toast.fromError(e, 'Launch failed');
    } finally {
      setBusy(false);
    }
  }, [workspaceId, targetId, nodes, edges, name, currentWorkflowId, navigate, toast]);

  // ---- Render ---------------------------------------------------------------
  const nodeTypes = useMemo(() => ({
    targetNode: TargetNode,
    toolNode: ToolNode,
  }), []);

  const toolNodeCount = nodes.filter((n) => n.data.kind === 'tool').length;
  const target = targets.find((t) => t.id === targetId) ?? null;

  return (
    <div className="grid wf-grid">
      <div className="card wf-toolbar">
        <div className="row" style={{ flex: 1, gap: 8, flexWrap: 'wrap' }}>
          <input
            className="input"
            style={{ maxWidth: 220 }}
            placeholder="Workflow name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <input
            className="input"
            style={{ maxWidth: 260 }}
            placeholder="Description (optional)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          <select
            className="input"
            style={{ maxWidth: 180 }}
            value={workspaceId ?? ''}
            onChange={(e) => { setWorkspaceId(e.target.value || null); setTargetId(null); }}
          >
            <option value="">— Workspace —</option>
            {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
          </select>
          <select
            className="input"
            style={{ maxWidth: 220 }}
            value={targetId ?? ''}
            onChange={(e) => setTargetId(e.target.value || null)}
          >
            <option value="">— Target —</option>
            {workspaceTargets.map((t) =>
              <option key={t.id} value={t.id}>{t.value}{t.active_allowed ? '' : ' (passive)'}</option>
            )}
          </select>
          {target && !target.active_allowed && (
            <span className="badge passive" title="Active scans require target authorization on the Targets page.">passive-only target</span>
          )}
          {currentWorkflowId && (
            <span className="badge ok" title={`Loaded server workflow ${currentWorkflowId}`}>
              <Cloud size={11} style={{ verticalAlign: 'middle', marginRight: 2 }} /> server-backed
            </span>
          )}
          <span className="muted small">{toolNodeCount} tool node{toolNodeCount === 1 ? '' : 's'} · {edges.length} edge{edges.length === 1 ? '' : 's'}</span>
        </div>
        <div className="row" style={{ gap: 6 }}>
          <button className="btn small" type="button" onClick={newWorkflow} title="New empty workflow"><FilePlus2 size={13} /> New</button>
          <div style={{ position: 'relative' }}>
            <button className="btn small" type="button" onClick={() => setShowLoadMenu((v) => !v)} title="Load a workflow from this browser"><FolderOpen size={13} /> Local</button>
            {showLoadMenu && (
              <SavedWorkflowMenu
                onClose={() => setShowLoadMenu(false)}
                onPick={loadWorkflow}
              />
            )}
          </div>
          <button className="btn small" type="button" onClick={saveCurrent} title="Save to this browser (localStorage)"><Save size={13} /> Save local</button>
          <div style={{ position: 'relative' }}>
            <button
              className="btn small"
              type="button"
              onClick={() => setShowCloudMenu((v) => !v)}
              title="Save / load / delete to the server"
            >
              <Cloud size={13} /> Cloud
            </button>
            {showCloudMenu && (
              <CloudWorkflowMenu
                workflows={cloudList}
                currentWorkflowId={currentWorkflowId}
                onClose={() => setShowCloudMenu(false)}
                onLoad={async (wf) => {
                  try {
                    const full = await api.workflow(wf.id);
                    hydrateFromServer(full);
                  } catch (e) { toast.fromError(e, 'Load failed'); }
                }}
                onSave={() => { setShowCloudMenu(false); cloudSave(false); }}
                onSaveAsNew={() => { setShowCloudMenu(false); cloudSave(true); }}
                onDelete={() => { setShowCloudMenu(false); cloudDelete(); }}
              />
            )}
          </div>
          <button className="btn" type="button" onClick={launch} disabled={busy || !targetId || toolNodeCount === 0}>
            <Rocket size={13} /> {busy ? 'Launching…' : 'Launch'}
          </button>
        </div>
      </div>

      <div className="wf-panes">
        <ToolPalette tools={tools} onAdd={addToolAtCenter} />
        <div
          className="wf-canvas-wrap"
          ref={canvasWrapperRef}
          onDragOver={onDragOver}
          onDrop={onDrop}
        >
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={(_, node) => setSelectedId(node.id)}
            onPaneClick={() => setSelectedId(null)}
            nodeTypes={nodeTypes}
            fitView
            proOptions={{ hideAttribution: true }}
          >
            <Background />
            <Controls />
          </ReactFlow>
        </div>
        <Inspector
          node={selected}
          onChange={updateSelectedTool}
          onDelete={deleteSelected}
          edges={edges}
          nodes={nodes}
        />
      </div>
    </div>
  );
}

/* ============================================================================
 * Saved workflow menu
 * ========================================================================== */

function CloudWorkflowMenu({
  workflows, currentWorkflowId, onClose, onLoad, onSave, onSaveAsNew, onDelete,
}: {
  workflows: SavedWorkflow[];
  currentWorkflowId: string | null;
  onClose: () => void;
  onLoad: (wf: SavedWorkflow) => void;
  onSave: () => void;
  onSaveAsNew: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="wf-saved-menu" onClick={(e) => e.stopPropagation()}>
      <div className="row space" style={{ padding: '6px 10px', borderBottom: '1px solid #1f2937' }}>
        <strong><Cloud size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Workspace workflows</strong>
        <button className="icon-btn" onClick={onClose} type="button" aria-label="Close"><X size={12} /></button>
      </div>
      {workflows.length === 0 ? (
        <p className="muted" style={{ padding: 10, margin: 0 }}>None yet — save your first one below.</p>
      ) : (
        workflows.map((wf) => (
          <button
            key={wf.id}
            type="button"
            className="wf-saved-pick"
            onClick={() => onLoad(wf)}
            title={wf.description ?? ''}
          >
            <strong>
              {wf.name}
              {wf.id === currentWorkflowId && <span className="badge passive" style={{ marginLeft: 6 }}>open</span>}
            </strong>
            <small className="muted">
              {(wf.body?.steps?.length ?? 0)} step{(wf.body?.steps?.length ?? 0) === 1 ? '' : 's'} · updated {new Date(wf.updated_at).toLocaleString()}
            </small>
          </button>
        ))
      )}
      <div className="wf-cloud-actions">
        <button type="button" className="btn small" onClick={onSave}>
          <CloudUpload size={12} /> {currentWorkflowId ? 'Save changes' : 'Save to workspace'}
        </button>
        <button type="button" className="btn small" onClick={onSaveAsNew}>
          Save as new
        </button>
        {currentWorkflowId && (
          <button type="button" className="btn small danger" onClick={onDelete}>
            <Trash2 size={12} /> Delete
          </button>
        )}
      </div>
    </div>
  );
}

function SavedWorkflowMenu({ onClose, onPick }: {
  onClose: () => void;
  onPick: (wf: LocalSavedWorkflow) => void;
}) {
  const [items, setItems] = useState<LocalSavedWorkflow[]>([]);

  useEffect(() => {
    setItems(Object.values(loadSavedWorkflows()).sort(
      (a, b) => (b.savedAt > a.savedAt ? 1 : -1),
    ));
  }, []);

  const remove = (name: string) => {
    const all = loadSavedWorkflows();
    delete all[name];
    persistSavedWorkflows(all);
    setItems(Object.values(all));
  };

  return (
    <div className="wf-saved-menu" onClick={(e) => e.stopPropagation()}>
      <div className="row space" style={{ padding: '6px 10px', borderBottom: '1px solid #1f2937' }}>
        <strong>Saved workflows</strong>
        <button className="icon-btn" onClick={onClose} type="button" aria-label="Close"><X size={12} /></button>
      </div>
      {items.length === 0 && <p className="muted" style={{ padding: 10, margin: 0 }}>None yet — save the current one.</p>}
      {items.map((wf) => (
        <div key={wf.name} className="wf-saved-item">
          <button type="button" className="wf-saved-pick" onClick={() => onPick(wf)} title="Load this workflow">
            <strong>{wf.name}</strong>
            <small className="muted">{wf.nodes.filter((n) => n.data.kind === 'tool').length} tools · saved {new Date(wf.savedAt).toLocaleString()}</small>
          </button>
          <button className="icon-btn" onClick={() => remove(wf.name)} type="button" aria-label={`Delete ${wf.name}`} title="Delete"><Trash2 size={12} /></button>
        </div>
      ))}
    </div>
  );
}

/* ============================================================================
 * Tool palette
 * ========================================================================== */

function ToolPalette({ tools, onAdd }: { tools: Tool[]; onAdd: (tool: Tool) => void }) {
  const [q, setQ] = useState('');
  const [category, setCategory] = useState('all');

  const categories = useMemo(
    () => ['all', ...Array.from(new Set(tools.map((t) => t.category))).sort()],
    [tools],
  );

  const filtered = useMemo(() => tools.filter((t) => {
    if (category !== 'all' && t.category !== category) return false;
    if (!q) return true;
    const hay = `${t.id} ${t.name} ${t.description} ${(t.tags ?? []).join(' ')}`.toLowerCase();
    return hay.includes(q.toLowerCase());
  }), [tools, q, category]);

  const onDragStart = (e: DragEvent<HTMLDivElement>, toolId: string) => {
    e.dataTransfer.setData('application/reactflow-tool', toolId);
    e.dataTransfer.effectAllowed = 'move';
  };

  return (
    <aside className="card wf-palette">
      <div className="row space"><strong><Boxes size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Tools</strong><span className="muted small">{filtered.length}/{tools.length}</span></div>
      <div className="row" style={{ position: 'relative', marginTop: 6 }}>
        <Search size={12} style={{ position: 'absolute', left: 8, opacity: 0.5 }} />
        <input
          className="input"
          style={{ paddingLeft: 26 }}
          placeholder="Search tools, tags…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>
      <select className="input" style={{ marginTop: 6 }} value={category} onChange={(e) => setCategory(e.target.value)}>
        {categories.map((c) => <option key={c} value={c}>{c}</option>)}
      </select>
      <div className="wf-palette-list">
        {filtered.length === 0 && <p className="muted small">No tools match.</p>}
        {filtered.map((t) => (
          <div
            key={t.id}
            className="wf-palette-tool"
            draggable
            onDragStart={(e) => onDragStart(e, t.id)}
            onDoubleClick={() => onAdd(t)}
            title={`${t.description}\n\nDouble-click to add at the center; drag onto the canvas to drop precisely.`}
          >
            <div className="row space">
              <strong>{t.name}</strong>
              <span className={`badge ${t.risk === 'passive' ? 'passive' : t.risk === 'high_active' ? 'bad' : 'active'}`}>{t.risk}</span>
            </div>
            <div className="muted small wf-palette-cat">{t.category}</div>
            <div className="wf-palette-io">
              {(t.inputs ?? []).map((io) => (
                <span key={`in-${io.name}`} className="wf-io-pill in" style={{ borderColor: typeColor(io.type) }}>
                  ◂ {io.type}
                </span>
              ))}
              {(t.outputs ?? []).map((io) => (
                <span key={`out-${io.name}`} className="wf-io-pill out" style={{ borderColor: typeColor(io.type) }}>
                  {io.type} ▸
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}

/* ============================================================================
 * Node renderers
 * ========================================================================== */

function TargetNode(props: NodeProps) {
  const data = props.data as TargetNodeData;
  return (
    <div className="wf-node target">
      <div className="wf-node-header">
        <Crosshair size={12} />
        <strong>Target</strong>
      </div>
      <div className="wf-node-body">
        <span className="mono small">{data.label}</span>
        {!data.targetId && <small className="muted">Pick a target above</small>}
      </div>
      <Handle
        id="out:target"
        type="source"
        position={Position.Right}
        style={{ background: typeColor('target_string'), top: '60%' }}
      />
    </div>
  );
}

function ToolNode(props: NodeProps) {
  const data = props.data as ToolNodeData;
  const tool = data.tool;
  const inputs = tool.inputs ?? [];
  const outputs = tool.outputs ?? [];
  return (
    <div className="wf-node tool">
      <div className="wf-node-header">
        <Settings2 size={12} />
        <strong>{tool.name}</strong>
        <span className={`badge ${tool.risk === 'passive' ? 'passive' : tool.risk === 'high_active' ? 'bad' : 'active'}`}>{tool.risk}</span>
      </div>
      <div className="wf-node-body">
        <small className="muted">{tool.category}</small>
        {data.argv_extra?.length || data.argv_replace?.length ? (
          <small className="badge ok" title="argv overrides applied">argv</small>
        ) : null}
      </div>
      {inputs.map((io, i) => (
        <div key={`in-${io.name}`} className="wf-node-handle in" style={{ top: 38 + i * 22 }}>
          <Handle
            id={`in:${io.name}`}
            type="target"
            position={Position.Left}
            style={{ background: typeColor(io.type) }}
          />
          <span className="wf-node-handle-label">{io.name}<small className="muted"> · {io.type}</small></span>
        </div>
      ))}
      {outputs.map((io, i) => (
        <div key={`out-${io.name}`} className="wf-node-handle out" style={{ top: 38 + i * 22 }}>
          <span className="wf-node-handle-label">{io.name}<small className="muted"> · {io.type}</small></span>
          <Handle
            id={`out:${io.name}`}
            type="source"
            position={Position.Right}
            style={{ background: typeColor(io.type) }}
          />
        </div>
      ))}
    </div>
  );
}

function handleType(node: WfNode, handleId: string | null | undefined, direction: 'in' | 'out'): string | null {
  if (node.data.kind === 'target') return direction === 'out' ? 'target_string' : null;
  const tool = node.data.tool;
  if (!handleId) return null;
  const [prefix, name] = handleId.split(':');
  const list = (direction === 'in' ? tool.inputs : tool.outputs) ?? [];
  const expectedPrefix = direction === 'in' ? 'in' : 'out';
  if (prefix !== expectedPrefix) return null;
  const io = list.find((x) => x.name === name);
  return io?.type ?? null;
}

/* ============================================================================
 * Inspector
 * ========================================================================== */

function Inspector({
  node, onChange, onDelete, edges, nodes,
}: {
  node: WfNode | null;
  onChange: (updater: (d: ToolNodeData) => ToolNodeData) => void;
  onDelete: () => void;
  edges: Edge[];
  nodes: WfNode[];
}) {
  if (!node) {
    return (
      <aside className="card wf-inspector">
        <EmptyState
          icon={<Settings2 size={24} />}
          title="No node selected"
          body="Click a tool node on the canvas to edit its argv overrides, timeout, and retry policy. Drag tools from the left palette to start building."
        />
      </aside>
    );
  }
  if (node.data.kind === 'target') {
    return (
      <aside className="card wf-inspector">
        <h3><Crosshair size={14} style={{ verticalAlign: 'middle' }} /> Target node</h3>
        <p className="muted">The target node is fixed — pick a target from the top bar. Its output is a <code>target_string</code> consumable by any tool that takes a domain / url.</p>
      </aside>
    );
  }

  const data = node.data;
  const tool = data.tool;

  // Surface the artifact variables this node can reference. Incoming edges
  // give the operator the template strings they can drop into argv_extra.
  const incoming = edges.filter((e) => e.target === node.id);
  const upstreamTypes = new Set<string>();
  for (const e of incoming) {
    const src = nodes.find((n) => n.id === e.source);
    if (!src) continue;
    const t = handleType(src, e.sourceHandle, 'out');
    if (t) upstreamTypes.add(t);
  }

  const setText = (key: 'argv_replace' | 'argv_extra') => (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const lines = e.target.value.split('\n').map((s) => s.replace(/\r$/, ''));
    const trimmed = lines.length === 1 && lines[0] === '' ? [] : lines;
    onChange((d) => ({ ...d, [key]: trimmed }));
  };

  return (
    <aside className="card wf-inspector">
      <div className="row space">
        <h3 style={{ margin: 0 }}>{tool.name}</h3>
        <button className="icon-btn danger" onClick={onDelete} title="Remove this node" aria-label="Delete"><Trash2 size={12} /></button>
      </div>
      <p className="muted small">{tool.description}</p>
      <div className="row" style={{ flexWrap: 'wrap', gap: 4 }}>
        <span className="badge passive">{tool.category}</span>
        <span className={`badge ${tool.risk === 'passive' ? 'passive' : tool.risk === 'high_active' ? 'bad' : 'active'}`}>{tool.risk}</span>
        {tool.requires_authorization && <span className="badge active">auth required</span>}
      </div>

      <div className="wf-inspector-section">
        <strong>Default command</strong>
        <pre className="mono wf-argv">{(tool.command?.argv ?? []).join(' ') || '(none)'}</pre>
      </div>

      <div className="wf-inspector-section">
        <strong>argv_replace</strong>
        <small className="muted"> — one arg per line; empty leaves the default in place.</small>
        <textarea
          className="input wf-argv-input"
          rows={4}
          placeholder={'leave blank to use the default'}
          value={(data.argv_replace ?? []).join('\n')}
          onChange={setText('argv_replace')}
        />
      </div>

      <div className="wf-inspector-section">
        <strong>argv_extra</strong>
        <small className="muted"> — appended after the default.</small>
        <textarea
          className="input wf-argv-input"
          rows={3}
          placeholder={"-l\n{{upstream.domain_list.merged_path}}"}
          value={(data.argv_extra ?? []).join('\n')}
          onChange={setText('argv_extra')}
        />
      </div>

      <div className="wf-inspector-section">
        <strong>Run policy</strong>
        <div className="grid cols-2" style={{ gap: 6 }}>
          <label className="muted small">Timeout (s)
            <input className="input" type="number" min={1} max={86400}
                   value={data.timeout_seconds ?? tool.default_timeout_seconds ?? 900}
                   onChange={(e) => onChange((d) => ({ ...d, timeout_seconds: Number(e.target.value) || undefined }))} />
          </label>
          <label className="muted small">Max retries
            <input className="input" type="number" min={0} max={10}
                   value={data.max_retries ?? tool.max_retries ?? 0}
                   onChange={(e) => onChange((d) => ({ ...d, max_retries: Number(e.target.value) || 0 }))} />
          </label>
          <label className="muted small">Retry backoff (s)
            <input className="input" type="number" min={0} max={300} step={0.5}
                   value={data.retry_backoff_seconds ?? tool.retry_backoff_seconds ?? 1}
                   onChange={(e) => onChange((d) => ({ ...d, retry_backoff_seconds: Number(e.target.value) || 0 }))} />
          </label>
          <label className="row muted small" style={{ alignItems: 'center', gap: 6 }}>
            <input type="checkbox"
                   checked={data.continue_on_error ?? tool.continue_on_error ?? false}
                   onChange={(e) => onChange((d) => ({ ...d, continue_on_error: e.target.checked }))} />
            Continue on error
          </label>
        </div>
      </div>

      <div className="wf-inspector-section">
        <strong>Available variables</strong>
        <small className="muted"> — drop into argv_extra to consume upstream artifacts.</small>
        {upstreamTypes.size === 0 ? (
          <p className="muted small">No inbound edges yet. Connect upstream tool outputs (or the target node) into this node first.</p>
        ) : (
          <ul className="wf-var-list">
            {[...upstreamTypes].map((t) => (
              <li key={t}><code>{`{{upstream.${t}.merged_path}}`}</code></li>
            ))}
            <li><code>{`{{previous.stdout_path}}`}</code></li>
          </ul>
        )}
      </div>
    </aside>
  );
}
