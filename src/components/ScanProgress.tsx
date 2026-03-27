"use client";
import {
  Shield, Lock, Globe, Network, Radio, Cpu, Brain, CheckCircle2, Loader2, XCircle,
  FileSearch, Bug, Timer, Anchor, Search, Square, RotateCcw, Mail, ScrollText, Minus,
} from "lucide-react";

export type ModuleStatus = "pending" | "running" | "done" | "error" | "skipped";

export interface ModuleProgress {
  id: string;
  label: string;
  status: ModuleStatus;
  error?: string;
}

const ICONS: Record<string, React.ElementType> = {
  headers: Shield,
  source: FileSearch,
  ssl: Lock,
  dns: Globe,
  subdomains: Network,
  ports: Radio,
  virustotal: Bug,
  wpcron: Timer,
  googleDork: Search,
  takeover: Anchor,
  tech: Cpu,
  ai: Brain,
  mailAuth: Mail,
  siteMeta: ScrollText,
};

function StatusIcon({ status }: { status: ModuleStatus }) {
  if (status === "done") return <CheckCircle2 className="w-4 h-4 text-success" />;
  if (status === "running") return <Loader2 className="w-4 h-4 text-accent animate-spin" />;
  if (status === "error") return <XCircle className="w-4 h-4 text-danger" />;
  if (status === "skipped") return <Minus className="w-4 h-4 text-text-dim" />;
  return <div className="w-4 h-4 rounded-full border-2 border-border" />;
}

const SEC_PER_MODULE_HINT = 7;

export default function ScanProgress({
  modules,
  presetLabel,
  onCancel,
  onRetryModule,
}: {
  modules: ModuleProgress[];
  /** Quick vs Complete — shown in the hint line */
  presetLabel?: string;
  onCancel?: () => void;
  onRetryModule?: (id: string) => void;
}) {
  const done = modules.filter((m) => m.status === "done").length;
  const total = modules.length;
  const pct = Math.round((done / total) * 100);
  const running = modules.filter((m) => m.status === "running").length;
  const etaSec = Math.max(0, (total - done - running) * SEC_PER_MODULE_HINT);

  return (
    <div className="max-w-3xl mx-auto px-4 animate-fade-up">
      <div className="bg-surface border border-border rounded-xl p-6">
        <div className="flex items-center justify-between mb-4 gap-2 flex-wrap">
          <h3 className="text-sm font-semibold text-white">
            Scanning…{presetLabel ? <span className="text-text-dim font-normal"> ({presetLabel})</span> : null}
          </h3>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-text-muted">{done}/{total} modules</span>
            {etaSec > 0 && (
              <span className="text-[10px] text-text-dim" title="Rough ETA based on remaining modules">
                ~{etaSec}s left
              </span>
            )}
            {onCancel && (
              <button
                type="button"
                onClick={onCancel}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border border-border text-text-muted hover:text-white hover:border-danger/50 hover:bg-danger/10 transition-colors"
              >
                <Square className="w-3 h-3" />
                Cancel
              </button>
            )}
          </div>
        </div>
        <p className="text-[10px] text-text-dim mb-3">
          Parallel batch (Complete): source, SSL, mail DNS, site files, subdomains, ports, VirusTotal, wp-cron, Google dork — then takeover and AI.
          Quick scan runs a smaller parallel set (no crawl / subdomains / dorks / AI).
        </p>

        <div className="w-full h-1.5 bg-bg rounded-full overflow-hidden mb-6">
          <div
            className="h-full scan-progress-bar rounded-full transition-all duration-500"
            style={{ width: `${pct}%` }}
          />
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {modules.map((mod) => {
            const Icon = ICONS[mod.id] || Shield;
            return (
              <div
                key={mod.id}
                className={`flex items-center gap-2.5 p-2.5 rounded-lg transition-colors ${
                  mod.status === "running" ? "bg-accent/5 border border-accent/20" :
                  mod.status === "done" ? "bg-success/5 border border-success/20" :
                  mod.status === "error" ? "bg-danger/5 border border-danger/20" :
                  mod.status === "skipped" ? "bg-bg/80 border border-border/60 opacity-75" :
                  "bg-bg/50 border border-transparent"
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${
                  mod.status === "running" ? "text-accent" :
                  mod.status === "done" ? "text-success" :
                  mod.status === "error" ? "text-danger" :
                  mod.status === "skipped" ? "text-text-dim" :
                  "text-text-dim"
                }`} />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium text-white truncate">{mod.label}</div>
                  {mod.status === "error" && mod.error && (
                    <div className="text-[10px] text-danger/90 truncate mt-0.5" title={mod.error}>
                      {mod.error}
                    </div>
                  )}
                  {mod.status === "skipped" && mod.error && (
                    <div className="text-[10px] text-text-dim truncate mt-0.5" title={mod.error}>
                      {mod.error}
                    </div>
                  )}
                </div>
                {mod.status === "error" && onRetryModule && (
                  <button
                    type="button"
                    onClick={() => onRetryModule(mod.id)}
                    className="shrink-0 p-1 rounded text-text-dim hover:text-accent hover:bg-accent/10"
                    title="Retry this module"
                    aria-label={`Retry ${mod.label}`}
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                  </button>
                )}
                <StatusIcon status={mod.status} />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
