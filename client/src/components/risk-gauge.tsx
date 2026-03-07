import { cn } from "@/lib/utils";
import { Shield, ShieldAlert, ShieldX, ShieldCheck } from "lucide-react";

interface RiskGaugeProps {
  score: number;
  verdict: string;
  confidence: string;
  size?: "sm" | "lg";
}

function getScoreColor(score: number) {
  if (score >= 75) return { bg: "bg-red-500/15 dark:bg-red-500/20", text: "text-red-600 dark:text-red-400", ring: "ring-red-500/30" };
  if (score >= 50) return { bg: "bg-orange-500/15 dark:bg-orange-500/20", text: "text-orange-600 dark:text-orange-400", ring: "ring-orange-500/30" };
  if (score >= 25) return { bg: "bg-yellow-500/15 dark:bg-yellow-500/20", text: "text-yellow-600 dark:text-yellow-400", ring: "ring-yellow-500/30" };
  return { bg: "bg-emerald-500/15 dark:bg-emerald-500/20", text: "text-emerald-600 dark:text-emerald-400", ring: "ring-emerald-500/30" };
}

function getScoreIcon(score: number, className: string) {
  if (score >= 75) return <ShieldX className={className} />;
  if (score >= 50) return <ShieldAlert className={className} />;
  if (score >= 25) return <Shield className={className} />;
  return <ShieldCheck className={className} />;
}

export function RiskGauge({ score, verdict, confidence, size = "lg" }: RiskGaugeProps) {
  const colors = getScoreColor(score);
  const isLarge = size === "lg";

  return (
    <div className="flex flex-col items-center gap-3" data-testid="risk-gauge">
      <div
        className={cn(
          "relative flex items-center justify-center rounded-full ring-2",
          colors.bg,
          colors.ring,
          isLarge ? "w-32 h-32" : "w-20 h-20"
        )}
      >
        <div className="flex flex-col items-center">
          {getScoreIcon(score, cn(colors.text, isLarge ? "w-6 h-6 mb-1" : "w-4 h-4 mb-0.5"))}
          <span className={cn("font-mono font-bold", colors.text, isLarge ? "text-3xl" : "text-xl")} data-testid="text-risk-score">
            {score}
          </span>
        </div>
      </div>
      <div className="text-center">
        <p className={cn("font-semibold", colors.text, isLarge ? "text-lg" : "text-sm")} data-testid="text-verdict">
          {verdict}
        </p>
        <p className="text-xs text-muted-foreground capitalize" data-testid="text-confidence">
          {confidence} confidence
        </p>
      </div>
    </div>
  );
}

export function RiskBadge({ score, verdict }: { score: number; verdict: string }) {
  const colors = getScoreColor(score);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium",
        colors.bg,
        colors.text
      )}
      data-testid="badge-risk"
    >
      {getScoreIcon(score, "w-3 h-3")}
      {verdict} ({score})
    </span>
  );
}
