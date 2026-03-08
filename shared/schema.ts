import { z } from "zod";

export const emailInputSchema = z.object({
  fromEmail: z.string().max(320).default(""),
  subject: z.string().max(1000).default(""),
  bodyText: z.string().max(100000).default(""),
  replyTo: z.string().max(320).default(""),
  returnPath: z.string().max(320).default(""),
  rawHeaders: z.string().max(200000).default(""),
  links: z.array(z.object({
    text: z.string().max(2000).default(""),
    href: z.string().max(2000).default(""),
  })).max(50).default([]),
  attachments: z.array(z.object({
    filename: z.string().max(500).default(""),
  })).max(50).default([]),
  observedBrandDomains: z.array(z.string().max(253)).max(100).default([]),
});

export type EmailInput = z.infer<typeof emailInputSchema>;

export interface AuthDetail {
  status: string;
  detail: string;
}

export interface TfidfDetail {
  phishingScore: number;
  topTerms: Array<{ term: string; tfidf: number }>;
  totalTermsMatched: number;
}

export interface SvmDetail {
  phishingProbability: number;
  confidence: number;
  svmScore: number;
  topFeatures: Array<{ feature: string; weight: number }>;
  featureCount: number;
}

export interface BertDetail {
  phishingProbability: number;
  confidence: number;
  tokenCount?: number;
  attentionInsights?: Array<{ token: string; importance: number }>;
  modelVersion: string;
  modelSource: "real" | "simulated";
  label?: string;
}

export interface ImpersonationDetail {
  detected: boolean;
  impersonatedBrand: string;
  method: string;
}

export interface TimeAnomalyDetail {
  sendHour: number | null;
  sendDay: string | null;
  anomalyType: string;
}

export interface UrlReputationDetail {
  domainAge: number | null;
  domainCreationDate: string | null;
  ageRiskScore: number;
  tldRiskScore: number;
  hostingRiskScore: number;
  totalScore: number;
  findings: string[];
  technical: Record<string, string>;
}

export interface ThreatSignalDetail {
  type: string;
  severity: "high" | "medium" | "low";
  description: string;
}

export interface ThreatIntelDetail {
  score: number;
  findings: string[];
  signals: ThreatSignalDetail[];
  domainEntropy: number;
  matchedIndicators: string[];
}

export interface HeaderAnalysisDetail {
  spf: AuthDetail;
  dkim: AuthDetail;
  dmarc: AuthDetail;
  receivedHops: number;
  headersParsed: boolean;
  spfMailFrom?: string;
  spfAligned?: boolean;
  dkimDomain?: string;
  dkimSelector?: string;
  dkimAligned?: boolean;
  dmarcHeaderFrom?: string;
  dmarcAligned?: boolean;
  sourceIp?: string | null;
  sourceHost?: string | null;
}

export interface InfrastructureAnalysisDetail {
  score: number;
  sourceIp: string | null;
  sourceHost: string | null;
  detectedProvider: string;
  expectedProvider: string | null;
  alignment: "aligned" | "mismatch" | "unknown";
  matchedRange: string | null;
  ipType: string;
  findings: string[];
}

export interface AnalysisResult {
  riskScore: number;
  verdict: string;
  confidence: string;
  reasons: string[];
  userActions: string[];
  technicalDetails: Record<string, string>;
  headerAnalysis?: HeaderAnalysisDetail;
  tfidfAnalysis?: TfidfDetail;
  svmAnalysis?: SvmDetail;
  bertAnalysis?: BertDetail;
  impersonation?: ImpersonationDetail;
  timeAnomaly?: TimeAnomalyDetail;
  urlReputation?: UrlReputationDetail;
  threatIntel?: ThreatIntelDetail;
  infrastructureAnalysis?: InfrastructureAnalysisDetail;
}
