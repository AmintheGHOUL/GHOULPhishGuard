import { z } from "zod";

export const emailInputSchema = z.object({
  fromEmail: z.string().default(""),
  subject: z.string().default(""),
  bodyText: z.string().default(""),
  replyTo: z.string().default(""),
  returnPath: z.string().default(""),
  rawHeaders: z.string().default(""),
  links: z.array(z.object({
    text: z.string().default(""),
    href: z.string().default(""),
  })).default([]),
  attachments: z.array(z.object({
    filename: z.string().default(""),
  })).default([]),
  observedBrandDomains: z.array(z.string()).default([]),
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
}
