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
  tokenCount: number;
  attentionInsights: Array<{ token: string; importance: number }>;
  modelVersion: string;
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

export interface AnalysisResult {
  riskScore: number;
  verdict: string;
  confidence: string;
  reasons: string[];
  userActions: string[];
  technicalDetails: Record<string, string>;
  headerAnalysis?: {
    spf: AuthDetail;
    dkim: AuthDetail;
    dmarc: AuthDetail;
    receivedHops: number;
    headersParsed: boolean;
  };
  tfidfAnalysis?: TfidfDetail;
  svmAnalysis?: SvmDetail;
  bertAnalysis?: BertDetail;
  impersonation?: ImpersonationDetail;
  timeAnomaly?: TimeAnomalyDetail;
}
