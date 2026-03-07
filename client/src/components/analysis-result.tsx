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
  Brain,
  BarChart3,
  Globe,
  Clock,
} from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { sanitizePlain } from "@/lib/sanitize";

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

      {result.impersonation?.detected && (
        <Card className="border-red-500/30 bg-red-500/5">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2 text-red-600 dark:text-red-400">
              <Globe className="w-4 h-4" />
              Domain Impersonation Detected
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm" data-testid="impersonation-brand">
              This sender appears to impersonate <span className="font-semibold">{sanitizePlain(result.impersonation.impersonatedBrand)}</span>
            </p>
            <p className="text-xs text-muted-foreground mt-1" data-testid="impersonation-method">
              Detection method: {
                result.impersonation.method === "typosquatting" ? "Typosquatting (Levenshtein distance)" :
                result.impersonation.method === "homoglyph" ? "Look-alike characters (homoglyph)" :
                result.impersonation.method === "brand-in-subdomain" ? "Brand name in fake domain" :
                result.impersonation.method === "keyword-match" ? "Brand keyword in domain" :
                result.impersonation.method
              }
            </p>
          </CardContent>
        </Card>
      )}

      {result.timeAnomaly && result.timeAnomaly.anomalyType && (
        <Card className="border-orange-500/30 bg-orange-500/5">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2 text-orange-600 dark:text-orange-400">
              <Clock className="w-4 h-4" />
              Unusual Send Time
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm" data-testid="time-anomaly-info">
              Sent on {result.timeAnomaly.sendDay} at {result.timeAnomaly.sendHour}:00 UTC
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {result.timeAnomaly.anomalyType === "weekend-night"
                ? "Weekend late-night emails are a common phishing pattern"
                : "Emails sent during unusual hours may indicate automated phishing campaigns"}
            </p>
          </CardContent>
        </Card>
      )}

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

      {result.tfidfAnalysis && result.tfidfAnalysis.totalTermsMatched > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Brain className="w-4 h-4 text-muted-foreground" />
              TF-IDF Text Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between" data-testid="tfidf-score">
                <span className="text-xs text-muted-foreground">Phishing Language Score</span>
                <span className={cn(
                  "text-sm font-semibold",
                  result.tfidfAnalysis.phishingScore >= 50 ? "text-red-500" :
                  result.tfidfAnalysis.phishingScore >= 25 ? "text-orange-500" :
                  "text-emerald-500"
                )}>
                  {result.tfidfAnalysis.phishingScore}/100
                </span>
              </div>
              <div className="w-full bg-muted rounded-full h-1.5">
                <div
                  className={cn(
                    "h-1.5 rounded-full transition-all",
                    result.tfidfAnalysis.phishingScore >= 50 ? "bg-red-500" :
                    result.tfidfAnalysis.phishingScore >= 25 ? "bg-orange-500" :
                    "bg-emerald-500"
                  )}
                  style={{ width: `${Math.min(result.tfidfAnalysis.phishingScore, 100)}%` }}
                />
              </div>
              {result.tfidfAnalysis.topTerms.length > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                    <BarChart3 className="w-3 h-3" />
                    Top phishing indicators by TF-IDF weight
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {result.tfidfAnalysis.topTerms.map((t, i) => (
                      <span
                        key={i}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-muted text-xs font-mono"
                        data-testid={`tfidf-term-${i}`}
                      >
                        {t.term}
                        <span className="text-muted-foreground">
                          {t.tfidf.toFixed(3)}
                        </span>
                      </span>
                    ))}
                  </div>
                </div>
              )}
              <p className="text-xs text-muted-foreground" data-testid="tfidf-terms-matched">
                {result.tfidfAnalysis.totalTermsMatched} phishing-related term{result.tfidfAnalysis.totalTermsMatched !== 1 ? "s" : ""} detected
              </p>
            </div>
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
