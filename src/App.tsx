import { useState } from "react";
import { useEcosystem } from "./hooks/useEcosystem";
import OverviewTab from "./components/OverviewTab";
import GraphTab from "./components/GraphTab";
import SimulationTab from "./components/SimulationTab";
import MitigationTab from "./components/MitigationTab";

type Tab = "overview" | "graph" | "simulate" | "mitigate";

const TABS: { id: Tab; label: string; icon: (active: boolean) => React.ReactNode }[] = [
  {
    id: "overview",
    label: "Overview",
    icon: (active) => (
      <svg className={`h-4 w-4 ${active ? "text-indigo-400" : "text-zinc-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 012-2h2a2 2 0 012 2v6m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
  },
  {
    id: "graph",
    label: "Ecosystem Graph",
    icon: (active) => (
      <svg className={`h-4 w-4 ${active ? "text-indigo-400" : "text-zinc-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
  },
  {
    id: "simulate",
    label: "Compromise Simulator",
    icon: (active) => (
      <svg className={`h-4 w-4 ${active ? "text-rose-400" : "text-zinc-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    ),
  },
  {
    id: "mitigate",
    label: "Mitigation Playbook",
    icon: (active) => (
      <svg className={`h-4 w-4 ${active ? "text-emerald-400" : "text-zinc-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
];

export default function App() {
  const eco = useEcosystem();
  const [tab, setTab] = useState<Tab>("overview");

  function jumpToSimulation(pkgId: string) {
    eco.selectCustomPackage(pkgId);
    setTab("simulate");
  }

  function jumpToNode(id: string) {
    eco.setSelectedNodeId(id);
    setTab("graph");
  }

  return (
    <div className="min-h-screen bg-[#0b0c10] text-zinc-100 selection:bg-indigo-500/30 selection:text-indigo-200">
      {/* Background ambient lighting */}
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-indigo-900/10 via-[#0b0c10] to-[#0b0c10]" />

      <header className="sticky top-0 z-40 border-b border-white/[0.08] bg-[#101217]/90 backdrop-blur-md">
        <div className="mx-auto flex max-w-[1440px] flex-wrap items-center justify-between gap-4 px-6 py-3.5">
          <div className="flex items-center gap-3">
            <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 via-indigo-600 to-violet-700 text-white shadow-lg shadow-indigo-500/20 ring-1 ring-white/20">
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L5.605 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
              </svg>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-tight text-white">DepRisk Sentinel</h1>
                <span className="flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Live Risk Engine
                </span>
              </div>
              <p className="text-xs text-zinc-400">Supply chain security & propagation risk graph</p>
            </div>
          </div>

          <nav className="flex items-center gap-1.5 rounded-xl border border-white/[0.08] bg-[#161820] p-1.5">
            {TABS.map((t) => {
              const active = tab === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all duration-200 ${
                    active
                      ? "border border-white/10 bg-indigo-600/20 text-white shadow-sm shadow-indigo-500/10 ring-1 ring-indigo-500/30"
                      : "text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-200"
                  }`}
                >
                  {t.icon(active)}
                  <span>{t.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-[1440px] px-6 py-6">
        {tab === "overview" && (
          <OverviewTab nodes={eco.nodes} metrics={eco.metrics} onSelect={jumpToNode} onSimulate={jumpToSimulation} />
        )}
        {tab === "graph" && (
          <GraphTab
            nodes={eco.nodes}
            edges={eco.edges}
            nodeById={eco.nodeById}
            metrics={eco.metrics}
            selectedNodeId={eco.selectedNodeId}
            setSelectedNodeId={eco.setSelectedNodeId}
            onSimulate={jumpToSimulation}
          />
        )}
        {tab === "simulate" && (
          <SimulationTab
            nodes={eco.nodes}
            edges={eco.edges}
            nodeById={eco.nodeById}
            metrics={eco.metrics}
            scenarios={eco.scenarios}
            activeScenario={eco.activeScenario}
            compromisedId={eco.compromisedId}
            propagation={eco.propagation}
            hopFilter={eco.hopFilter}
            setHopFilter={eco.setHopFilter}
            onSelectScenario={eco.selectScenario}
            onSelectCustom={eco.selectCustomPackage}
            onGoToMitigation={() => setTab("mitigate")}
          />
        )}
        {tab === "mitigate" && (
          <MitigationTab
            nodes={eco.nodes}
            edges={eco.edges}
            nodeById={eco.nodeById}
            metrics={eco.metrics}
            compromisedId={eco.compromisedId}
            propagation={eco.propagation}
            onSelect={jumpToNode}
          />
        )}
      </main>

      <footer className="mx-auto max-w-[1440px] border-t border-white/[0.06] px-6 py-6 text-center text-xs text-zinc-500">
        Simulated security ecosystem for risk telemetry and blast-radius analysis — packages and vulnerability vectors modeled on real-world supply chain incident patterns.
      </footer>
    </div>
  );
}

