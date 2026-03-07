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
  Zap,
  Layers,
  Search,
  Database,
  Calendar,
  Server,
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

function ProbabilityBar({ probability, label }: { probability: number; label: string }) {
  const pct = Math.round(probability * 100);
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">{label}</span>
        <span className={cn(
          "text-sm font-semibold",
          pct >= 70 ? "text-red-500" : pct >= 40 ? "text-orange-500" : "text-emerald-500"
        )}>
          {pct}%
        </span>
      </div>
      <div className="w-full bg-muted rounded-full h-1.5">
        <div
          className={cn(
            "h-1.5 rounded-full transition-all",
            pct >= 70 ? "bg-red-500" : pct >= 40 ? "bg-orange-500" : "bg-emerald-500"
          )}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
      </div>
    </div>
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

      {result.urlReputation && result.urlReputation.totalScore > 0 && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2 text-amber-600 dark:text-amber-400">
              <Search className="w-4 h-4" />
              URL Reputation Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center gap-4 flex-wrap">
                <div className="flex items-center gap-1.5 text-xs" data-testid="url-rep-score">
                  <span className="text-muted-foreground">Risk Score:</span>
                  <span className={cn(
                    "font-semibold",
                    result.urlReputation.totalScore >= 15 ? "text-red-500" :
                    result.urlReputation.totalScore >= 8 ? "text-orange-500" : "text-amber-500"
                  )}>
                    {result.urlReputation.totalScore}
                  </span>
                </div>
                {result.urlReputation.domainAge !== null && (
                  <div className="flex items-center gap-1.5 text-xs" data-testid="url-rep-age">
                    <Calendar className="w-3 h-3 text-muted-foreground" />
                    <span className="text-muted-foreground">Domain Age:</span>
                    <span className="font-mono font-medium">
                      {result.urlReputation.domainAge < 1 ? "< 1 day" :
                       result.urlReputation.domainAge === 1 ? "1 day" :
                       `${result.urlReputation.domainAge} days`}
                    </span>
                  </div>
                )}
                {result.urlReputation.domainCreationDate && (
                  <div className="flex items-center gap-1.5 text-xs" data-testid="url-rep-created">
                    <span className="text-muted-foreground">Created:</span>
                    <span className="font-mono">{new Date(result.urlReputation.domainCreationDate).toLocaleDateString()}</span>
                  </div>
                )}
              </div>
              {result.urlReputation.findings.length > 0 && (
                <ul className="space-y-1.5">
                  {result.urlReputation.findings.map((finding, i) => (
                    <li key={i} className="flex gap-2 text-xs" data-testid={`url-rep-finding-${i}`}>
                      <AlertTriangle className="w-3 h-3 text-amber-500 mt-0.5 shrink-0" />
                      <span>{finding}</span>
                    </li>
                  ))}
                </ul>
              )}
              <div className="flex gap-3 flex-wrap">
                {result.urlReputation.ageRiskScore > 0 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-600 dark:text-red-400" data-testid="url-rep-badge-age">
                    Age Risk +{result.urlReputation.ageRiskScore}
                  </span>
                )}
                {result.urlReputation.tldRiskScore > 0 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-600 dark:text-orange-400" data-testid="url-rep-badge-tld">
                    TLD Risk +{result.urlReputation.tldRiskScore}
                  </span>
                )}
                {result.urlReputation.hostingRiskScore > 0 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400" data-testid="url-rep-badge-hosting">
                    Hosting Risk +{result.urlReputation.hostingRiskScore}
                  </span>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {result.threatIntel && result.threatIntel.score > 0 && (
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2 text-purple-600 dark:text-purple-400">
              <Database className="w-4 h-4" />
              Threat Intelligence
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center gap-4 flex-wrap">
                <div className="flex items-center gap-1.5 text-xs" data-testid="threat-intel-score">
                  <span className="text-muted-foreground">Threat Score:</span>
                  <span className={cn(
                    "font-semibold",
                    result.threatIntel.score >= 25 ? "text-red-500" :
                    result.threatIntel.score >= 10 ? "text-orange-500" : "text-amber-500"
                  )}>
                    {result.threatIntel.score}
                  </span>
                </div>
                {result.threatIntel.domainEntropy > 0 && (
                  <div className="flex items-center gap-1.5 text-xs" data-testid="threat-intel-entropy">
                    <span className="text-muted-foreground">Domain Entropy:</span>
                    <span className="font-mono">{result.threatIntel.domainEntropy}</span>
                  </div>
                )}
              </div>

              {result.threatIntel.signals.length > 0 && (
                <div className="space-y-2">
                  {result.threatIntel.signals.map((signal, i) => (
                    <div key={i} className="flex gap-2 items-start text-xs" data-testid={`threat-signal-${i}`}>
                      <span className={cn(
                        "shrink-0 mt-0.5 w-1.5 h-1.5 rounded-full",
                        signal.severity === "high" ? "bg-red-500" :
                        signal.severity === "medium" ? "bg-orange-500" : "bg-amber-500"
                      )} />
                      <span>{signal.description}</span>
                    </div>
                  ))}
                </div>
              )}

              {result.threatIntel.matchedIndicators.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {result.threatIntel.matchedIndicators.map((indicator, i) => (
                    <span
                      key={i}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-600 dark:text-purple-400 font-mono"
                      data-testid={`threat-indicator-${i}`}
                    >
                      {indicator}
                    </span>
                  ))}
                </div>
              )}
            </div>
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

      {(result.tfidfAnalysis || result.svmAnalysis || result.bertAnalysis) && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Layers className="w-4 h-4 text-muted-foreground" />
              ML Classifier Ensemble
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {result.tfidfAnalysis && result.tfidfAnalysis.totalTermsMatched > 0 && (
                <div className="space-y-3" data-testid="tfidf-section">
                  <div className="flex items-center gap-2">
                    <Brain className="w-3.5 h-3.5 text-muted-foreground" />
                    <span className="text-xs font-medium">TF-IDF Keyword Analysis</span>
                  </div>
                  <div data-testid="tfidf-score">
                    <ProbabilityBar probability={result.tfidfAnalysis.phishingScore / 100} label="Phishing Language Score" />
                  </div>
                  {result.tfidfAnalysis.topTerms.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1.5 flex items-center gap-1">
                        <BarChart3 className="w-3 h-3" />
                        Top indicators by TF-IDF weight
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
              )}

              {result.tfidfAnalysis && result.svmAnalysis && (
                <div className="border-t border-border" />
              )}

              {result.svmAnalysis && result.svmAnalysis.featureCount > 0 && (
                <div className="space-y-3" data-testid="svm-section">
                  <div className="flex items-center gap-2">
                    <Zap className="w-3.5 h-3.5 text-muted-foreground" />
                    <span className="text-xs font-medium">TF-IDF + Linear SVM</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                      {result.svmAnalysis.featureCount} features
                    </span>
                  </div>
                  <div data-testid="svm-probability">
                    <ProbabilityBar probability={result.svmAnalysis.phishingProbability} label="Phishing Probability" />
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>Decision score: <span className="font-mono">{result.svmAnalysis.svmScore}</span></span>
                    <span>Confidence: <span className="font-mono">{Math.round(result.svmAnalysis.confidence * 100)}%</span></span>
                  </div>
                  {result.svmAnalysis.topFeatures.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1.5">Top SVM features</p>
                      <div className="flex flex-wrap gap-1.5">
                        {result.svmAnalysis.topFeatures.slice(0, 8).map((f, i) => (
                          <span
                            key={i}
                            className={cn(
                              "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono",
                              f.weight > 0 ? "bg-red-500/10 text-red-600 dark:text-red-400" : "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                            )}
                            data-testid={`svm-feature-${i}`}
                          >
                            {f.feature}
                            <span className="opacity-70">{f.weight > 0 ? "+" : ""}{f.weight}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {result.svmAnalysis && result.bertAnalysis && (
                <div className="border-t border-border" />
              )}

              {result.bertAnalysis && (result.bertAnalysis.modelSource === "real" || (result.bertAnalysis.tokenCount && result.bertAnalysis.tokenCount > 2)) && (
                <div className="space-y-3" data-testid="bert-section">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Brain className="w-3.5 h-3.5 text-primary" />
                    <span className="text-xs font-medium">
                      {result.bertAnalysis.modelSource === "real" ? "DistilBERT (Real Model)" : "BERT Deep Learning"}
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                      result.bertAnalysis.modelSource === "real"
                        ? "bg-emerald-500/10 text-emerald-600"
                        : "bg-amber-500/10 text-amber-600"
                    }`}>
                      {result.bertAnalysis.modelSource === "real" ? "Real Model" : "Simulated"}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary">
                      {result.bertAnalysis.modelVersion}
                    </span>
                  </div>
                  <div data-testid="bert-probability">
                    <ProbabilityBar probability={result.bertAnalysis.phishingProbability} label="Phishing Probability" />
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
                    {result.bertAnalysis.label && (
                      <span>Classification: <span className="font-mono font-medium">{result.bertAnalysis.label}</span></span>
                    )}
                    {result.bertAnalysis.tokenCount && (
                      <span>Tokens: <span className="font-mono">{result.bertAnalysis.tokenCount}</span></span>
                    )}
                    <span>Confidence: <span className="font-mono">{Math.round(result.bertAnalysis.confidence * 100)}%</span></span>
                  </div>
                  {result.bertAnalysis.modelSource === "real" && result.bertAnalysis.phishingProbability >= 0.7 && (
                    <div className="bg-red-500/10 rounded-md p-2">
                      <p className="text-xs text-red-600 font-medium">
                        Real DistilBERT model trained on phishing emails flagged this content as phishing with {Math.round(result.bertAnalysis.phishingProbability * 100)}% confidence.
                      </p>
                    </div>
                  )}
                  {result.bertAnalysis.attentionInsights && result.bertAnalysis.attentionInsights.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1.5">Attention-weighted tokens</p>
                      <div className="flex flex-wrap gap-1.5">
                        {result.bertAnalysis.attentionInsights.map((insight, i) => (
                          <span
                            key={i}
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-primary/10 text-xs font-mono"
                            data-testid={`bert-token-${i}`}
                          >
                            {insight.token}
                            <span className="text-muted-foreground">{insight.importance}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
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
          className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground px-3 py-2 rounded-md w-full"
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
