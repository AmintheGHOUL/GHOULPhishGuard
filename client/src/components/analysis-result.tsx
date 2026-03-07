import type { AnalysisResult } from "@shared/schema";
import { RiskGauge } from "./risk-gauge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertTriangle,
  CheckCircle2,
  Info,
  Link as LinkIcon,
  Paperclip,
  Mail,
  FileText,
  ChevronDown,
  ShieldCheck,
  ShieldX,
  ShieldAlert,
} from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

interface AnalysisResultViewProps {
  result: AnalysisResult;
}

function AuthStatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    pass: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
    fail: "bg-red-500/15 text-red-600 dark:text-red-400",
    softfail: "bg-orange-500/15 text-orange-600 dark:text-orange-400",
    neutral: "bg-muted text-muted-foreground",
    none: "bg-muted text-muted-foreground",
    unknown: "bg-muted text-muted-foreground",
  };

  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded text-xs font-medium uppercase", colors[status] || colors.unknown)}>
      {status}
    </span>
  );
}

export function AnalysisResultView({ result }: AnalysisResultViewProps) {
  const [showTechnical, setShowTechnical] = useState(false);

  return (
    <div className="space-y-4" data-testid="analysis-result">
      <div className="flex justify-center py-4">
        <RiskGauge
          score={result.riskScore}
          verdict={result.verdict}
          confidence={result.confidence}
        />
      </div>

      {result.headerAnalysis?.headersParsed && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-muted-foreground" />
              Email Authentication
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-3">
              <div className="text-center space-y-1" data-testid="auth-spf">
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">SPF</p>
                <AuthStatusBadge status={result.headerAnalysis.spf.status} />
              </div>
              <div className="text-center space-y-1" data-testid="auth-dkim">
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">DKIM</p>
                <AuthStatusBadge status={result.headerAnalysis.dkim.status} />
              </div>
              <div className="text-center space-y-1" data-testid="auth-dmarc">
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">DMARC</p>
                <AuthStatusBadge status={result.headerAnalysis.dmarc.status} />
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-3 text-center" data-testid="text-received-hops">
              {result.headerAnalysis.receivedHops} server hop{result.headerAnalysis.receivedHops !== 1 ? "s" : ""} detected
            </p>
          </CardContent>
        </Card>
      )}

      {result.reasons.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-muted-foreground" />
              Findings
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2.5">
              {result.reasons.map((reason, i) => (
                <li key={i} className="flex gap-2.5 text-sm" data-testid={`text-reason-${i}`}>
                  <div className="mt-1.5 w-1.5 h-1.5 rounded-full bg-muted-foreground shrink-0" />
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-muted-foreground" />
            Recommended Actions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2.5">
            {result.userActions.map((action, i) => (
              <li key={i} className="flex gap-2.5 text-sm" data-testid={`text-action-${i}`}>
                <div className="mt-1.5 w-1.5 h-1.5 rounded-full bg-primary shrink-0" />
                <span>{action}</span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Info className="w-4 h-4 text-muted-foreground" />
            Overview
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="flex items-center gap-2 text-sm">
              <Mail className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              <div className="min-w-0">
                <p className="text-xs text-muted-foreground">Sender</p>
                <p className="font-mono text-xs truncate" data-testid="text-sender">{result.technicalDetails.sender || "unknown"}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <FileText className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              <div className="min-w-0">
                <p className="text-xs text-muted-foreground">Domain</p>
                <p className="font-mono text-xs" data-testid="text-domain">{result.technicalDetails.senderDomain || "unknown"}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <LinkIcon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              <div>
                <p className="text-xs text-muted-foreground">Links</p>
                <p className="font-mono text-xs" data-testid="text-links-count">{result.technicalDetails.linksFound || "0"}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Paperclip className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              <div>
                <p className="text-xs text-muted-foreground">Attachments</p>
                <p className="font-mono text-xs" data-testid="text-attachments-count">{result.technicalDetails.attachmentsFound || "0"}</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div>
        <button
          className="flex items-center gap-2 text-xs text-muted-foreground hover-elevate px-3 py-2 rounded-md w-full"
          onClick={() => setShowTechnical(!showTechnical)}
          data-testid="button-toggle-technical"
        >
          <ChevronDown className={cn("w-3.5 h-3.5 transition-transform", showTechnical && "rotate-180")} />
          Technical Details
        </button>
        {showTechnical && (
          <Card className="mt-2">
            <CardContent className="pt-4">
              <div className="space-y-2">
                {Object.entries(result.technicalDetails).map(([key, value]) => (
                  <div key={key} className="flex justify-between gap-4 text-xs" data-testid={`text-detail-${key}`}>
                    <span className="text-muted-foreground font-mono shrink-0">{key}</span>
                    <span className="font-mono truncate text-right">{value}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
