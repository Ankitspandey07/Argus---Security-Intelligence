"use client";
import { Code2, Layers } from "lucide-react";
import CodeReview from "@/components/CodeReview";
import DecodeTool from "@/components/DecodeTool";

export default function ToolsWorkspace() {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8 text-center lg:text-left">
        <h2 className="text-xl font-bold text-white tracking-tight">Developer workspace</h2>
        <p className="text-sm text-text-muted mt-1 max-w-2xl mx-auto lg:mx-0">
          AI code review beside an encoding lab — same screen, no scan required.
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-8 items-stretch">
        <section className="flex flex-col min-h-0">
          <div className="flex items-center gap-2 mb-3 text-text-dim">
            <Code2 className="w-4 h-4 text-accent" />
            <span className="text-xs font-semibold uppercase tracking-wider">Code security review</span>
          </div>
          <div className="flex-1 min-h-0">
            <CodeReview embedded />
          </div>
        </section>

        <section className="flex flex-col min-h-[480px] lg:min-h-0">
          <div className="flex items-center gap-2 mb-3 text-text-dim">
            <Layers className="w-4 h-4 text-accent" />
            <span className="text-xs font-semibold uppercase tracking-wider">Crypto / encoding lab</span>
          </div>
          <div className="flex-1 min-h-0">
            <DecodeTool />
          </div>
        </section>
      </div>
    </div>
  );
}
