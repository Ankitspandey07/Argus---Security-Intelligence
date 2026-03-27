"use client";
import { useEffect, useState } from "react";
import { Search, Zap, Globe, Code2, ArrowRight, KeyRound, Gauge, Layers } from "lucide-react";
import { useI18n } from "@/components/I18nProvider";
import { ARGUS_API_KEY_STORAGE } from "@/lib/argus-client-headers";
import type { ScanPreset } from "@/lib/scan-presets";

interface ScanFormProps {
  onScan: (target: string) => void;
  scanning: boolean;
  scanPreset: ScanPreset;
  onPresetChange: (p: ScanPreset) => void;
}

export default function ScanForm({ onScan, scanning, scanPreset, onPresetChange }: ScanFormProps) {
  const { t } = useI18n();
  const [input, setInput] = useState("");
  const [apiKey, setApiKey] = useState("");

  useEffect(() => {
    try {
      const k = localStorage.getItem(ARGUS_API_KEY_STORAGE);
      if (k) setApiKey(k);
    } catch {
      /* ignore */
    }
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim() && !scanning) onScan(input.trim());
  };

  const examples = [
    { label: "google.com", icon: Globe },
    { label: "github.com", icon: Code2 },
    { label: "stripe.com", icon: Zap },
  ];

  return (
    <div className="relative">
      <div className="absolute inset-0 bg-gradient-to-b from-accent/5 via-transparent to-transparent pointer-events-none rounded-3xl" />
      <div className="relative max-w-3xl mx-auto text-center pt-16 pb-12 px-4">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-accent/10 border border-accent/20 text-accent text-xs font-medium mb-6">
          <Zap className="w-3 h-3" />
          {t("scanForm.badge")}
        </div>

        <h2 className="text-4xl sm:text-5xl font-bold text-white tracking-tight mb-4">
          {t("scanForm.heroLine1")}
          <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-accent to-info">
            {t("scanForm.heroLine2")}
          </span>
        </h2>

        <p className="text-text-muted text-lg mb-6 max-w-xl mx-auto">
          {t("scanForm.intro")}
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-8 max-w-xl mx-auto">
          <span className="text-[10px] uppercase tracking-wider text-text-dim font-semibold shrink-0">
            {t("scanForm.scanDepth")}
          </span>
          <div className="inline-flex rounded-lg border border-border bg-bg p-1">
            <button
              type="button"
              onClick={() => onPresetChange("quick")}
              disabled={scanning}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                scanPreset === "quick"
                  ? "bg-accent text-white shadow-sm"
                  : "text-text-muted hover:text-white"
              }`}
            >
              <Gauge className="w-3.5 h-3.5" />
              {t("scanner.presetQuick")}
            </button>
            <button
              type="button"
              onClick={() => onPresetChange("complete")}
              disabled={scanning}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                scanPreset === "complete"
                  ? "bg-accent text-white shadow-sm"
                  : "text-text-muted hover:text-white"
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              {t("scanner.presetComplete")}
            </button>
          </div>
        </div>
        <p className="text-[11px] text-text-dim max-w-lg mx-auto mb-8 text-center">
          <strong className="text-text-muted">{t("scanner.presetQuick")}</strong> — {t("scanForm.presetQuickFeatures")}{" "}
          <strong className="text-text-muted">{t("scanner.presetComplete")}</strong> — {t("scanForm.presetCompleteFeatures")}
        </p>

        <form onSubmit={handleSubmit} className="relative max-w-2xl mx-auto">
          <div className="relative group">
            <div className="absolute -inset-0.5 bg-gradient-to-r from-accent/50 via-info/50 to-accent/50 rounded-xl opacity-0 group-focus-within:opacity-100 transition-opacity blur-sm" />
            <div className="relative flex items-center bg-surface border border-border rounded-xl overflow-hidden focus-within:border-accent/50 transition-colors">
              <Search className="w-5 h-5 text-text-dim ml-4 shrink-0" />
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={t("scanForm.targetPlaceholder")}
                className="flex-1 bg-transparent py-4 px-3 text-white placeholder:text-text-dim focus:outline-none font-mono text-sm"
                disabled={scanning}
              />
              <button
                type="submit"
                disabled={scanning || !input.trim()}
                className="m-1.5 px-6 py-2.5 bg-accent hover:bg-accent-hover text-white font-semibold text-sm rounded-lg disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2 shrink-0"
              >
                {scanning ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    {t("scanForm.scanning")}
                  </>
                ) : (
                  <>
                    {t("scanForm.analyze")}
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>
        </form>

        <div className="flex items-center justify-center gap-3 mt-6">
          <span className="text-xs text-text-dim">{t("scanForm.tryLabel")}</span>
          {examples.map((ex) => (
            <button
              key={ex.label}
              onClick={() => { setInput(ex.label); if (!scanning) onScan(ex.label); }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono text-text-muted hover:text-white hover:bg-surface-2 border border-transparent hover:border-border transition-all"
            >
              <ex.icon className="w-3 h-3" />
              {ex.label}
            </button>
          ))}
        </div>

        <details className="mt-8 max-w-xl mx-auto text-left rounded-xl border border-border/60 bg-surface/40 px-4 py-3">
          <summary className="text-xs text-text-muted cursor-pointer select-none flex items-center gap-2 list-none [&::-webkit-details-marker]:hidden">
            <KeyRound className="w-3.5 h-3.5 text-accent shrink-0" />
            {t("scanForm.apiKeySummary")}
          </summary>
          <p className="text-[10px] text-text-dim mt-2 mb-2">
            {t("scanForm.apiKeyHelpStart")}
            <span className="font-mono">ARGUS_API_KEY</span>
            {t("scanForm.apiKeyHelpMid")}
            <span className="font-mono">x-argus-key</span>
            {t("scanForm.apiKeyHelpEnd")}
          </p>
          <input
            type="password"
            autoComplete="off"
            value={apiKey}
            onChange={(e) => {
              const v = e.target.value;
              setApiKey(v);
              try {
                if (v) localStorage.setItem(ARGUS_API_KEY_STORAGE, v);
                else localStorage.removeItem(ARGUS_API_KEY_STORAGE);
              } catch {
                /* ignore */
              }
            }}
            placeholder={t("scanForm.apiKeyPlaceholder")}
            className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-xs font-mono text-white placeholder:text-text-dim focus:outline-none focus:ring-2 focus:ring-accent/40"
          />
        </details>
      </div>
    </div>
  );
}
