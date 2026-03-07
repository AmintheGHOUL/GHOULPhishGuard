import { analyzeContent } from "./contentRules";
import { extractFirstHttpLink, findDomainMismatch } from "./reputation";
import { safeUrl, getDomainFromEmail, getBaseDomain } from "./domains";
import { parseEmailHeaders, headerAuthFindings, hasRealAuthHeaders } from "./headerParser";
import { classifyWithTfidf } from "./tfidfClassifier";
import { classifyWithSvm } from "./svmClassifier";
import { classifyWithBert } from "./bertClassifier";
import { classifyWithRealBert } from "./realBertClassifier";
import { detectDomainImpersonation } from "./domainImpersonation";
import { detectTimeAnomaly, extractDateFromHeaders } from "./timeAnomaly";
import type { EmailInput, AnalysisResult } from "@shared/schema";

function detectSuspiciousAttachments(attachments: Array<{ filename: string }> = []) {
  const riskyExts = [".zip", ".exe", ".js", ".iso", ".html", ".docm", ".xlsm", ".scr"];
  const found = attachments
    .map((a) => a.filename || "")
    .filter((name) => riskyExts.some((ext) => name.toLowerCase().endsWith(ext)));

  return {
    score: found.length ? 12 : 0,
    findings: found.length
      ? [`This email contains risky attachment types: ${found.join(", ")}.`]
      : [],
  };
}

function detectLinkDeception(
  links: Array<{ text: string; href: string }> = [],
  observedBrands: string[] = []
) {
  let score = 0;
  const findings: string[] = [];
  const technical: Record<string, string> = {};

  for (const link of links) {
    const parsed = safeUrl(link.href);
    if (!parsed) continue;
    const baseDomain = getBaseDomain(parsed.hostname);

    if (link.text && /^https?:/i.test(link.text) && link.text !== link.href) {
      score += 15;
      findings.push("A visible link does not match the real destination behind it.");
    }

    for (const brand of observedBrands) {
      if (
        parsed.hostname.toLowerCase().includes(brand.split(".")[0]) &&
        baseDomain !== brand
      ) {
        score += 25;
        findings.push(
          `A link tries to look like ${brand}, but the real website is ${baseDomain}.`
        );
      }
    }

    technical.primaryLinkDomain = baseDomain;
    technical.primaryLink = link.href;
  }

  return { score, findings, technical };
}

function verdictFromScore(score: number): string {
  if (score >= 75) return "Likely phishing";
  if (score >= 50) return "High risk";
  if (score >= 25) return "Suspicious";
  return "Low risk";
}

function confidenceFromScore(score: number): string {
  if (score >= 75) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function dedupe(items: string[]): string[] {
  return Array.from(new Set(items)).slice(0, 12);
}

export async function analyzeEmail(email: EmailInput): Promise<AnalysisResult> {
  const bodyText = email.bodyText || "";
  const subject = email.subject || "";
  const rawHeaders = email.rawHeaders || "";
  let fromEmail = (email.fromEmail || "").toLowerCase();
  let replyTo = (email.replyTo || "").toLowerCase();
  let returnPath = (email.returnPath || "").toLowerCase();
  const attachments = email.attachments || [];
  const links = email.links || [];
  const observedBrands = email.observedBrandDomains || [];

  let score = 0;
  const reasons: string[] = [];
  let headerAnalysis: AnalysisResult["headerAnalysis"] = undefined;

  if (rawHeaders && hasRealAuthHeaders(rawHeaders)) {
    const parsed = parseEmailHeaders(rawHeaders);

    if (!fromEmail && parsed.from) fromEmail = parsed.from.toLowerCase();
    if (!replyTo && parsed.replyTo) replyTo = parsed.replyTo.toLowerCase();
    if (!returnPath && parsed.returnPath) returnPath = parsed.returnPath.toLowerCase();

    const authFindings = headerAuthFindings(parsed);
    score += authFindings.score;
    reasons.push(...authFindings.findings);

    headerAnalysis = {
      spf: parsed.spf,
      dkim: parsed.dkim,
      dmarc: parsed.dmarc,
      receivedHops: parsed.receivedChain.length,
      headersParsed: true,
    };
  } else if (rawHeaders) {
    const parsed = parseEmailHeaders(rawHeaders);
    if (!fromEmail && parsed.from) fromEmail = parsed.from.toLowerCase();
    if (!replyTo && parsed.replyTo) replyTo = parsed.replyTo.toLowerCase();
    if (!returnPath && parsed.returnPath) returnPath = parsed.returnPath.toLowerCase();
  }

  const senderBaseDomain = getBaseDomain(getDomainFromEmail(fromEmail));

  const technicalDetails: Record<string, string> = {
    sender: fromEmail || "unknown",
    subject: subject || "none",
    linksFound: String(links.length),
    attachmentsFound: String(attachments.length),
    senderDomain: senderBaseDomain || "unknown",
  };

  const senderFullDomain = getDomainFromEmail(fromEmail);
  const impersonationCheck = detectDomainImpersonation(senderFullDomain);
  let impersonation: AnalysisResult["impersonation"] = undefined;
  if (impersonationCheck.detected) {
    score += impersonationCheck.score;
    reasons.push(...impersonationCheck.findings);
    Object.assign(technicalDetails, impersonationCheck.technical);
    impersonation = {
      detected: true,
      impersonatedBrand: impersonationCheck.impersonatedBrand,
      method: impersonationCheck.method,
    };
  }

  let timeAnomaly: AnalysisResult["timeAnomaly"] = undefined;
  const dateHeader = rawHeaders ? extractDateFromHeaders(rawHeaders) : "";
  if (dateHeader) {
    const timeCheck = detectTimeAnomaly(dateHeader);
    if (timeCheck.score > 0) {
      score += timeCheck.score;
      reasons.push(...timeCheck.findings);
    }
    if (timeCheck.sendHour !== null) {
      timeAnomaly = {
        sendHour: timeCheck.sendHour,
        sendDay: timeCheck.sendDay,
        anomalyType: timeCheck.anomalyType,
      };
      technicalDetails.sendTime = `${timeCheck.sendDay} ${timeCheck.sendHour}:00 UTC`;
    }
  }

  const contentAnalysis = analyzeContent(bodyText, subject, links);
  score += contentAnalysis.score;
  reasons.push(...contentAnalysis.findings);

  const attachmentAnalysis = detectSuspiciousAttachments(attachments);
  score += attachmentAnalysis.score;
  reasons.push(...attachmentAnalysis.findings);

  const mismatch = findDomainMismatch(fromEmail, replyTo, returnPath);
  if (mismatch.replyMismatch) {
    score += 20;
    reasons.push(
      `The reply address belongs to ${mismatch.replyDomain}, which does not match the sender's domain.`
    );
  }
  if (mismatch.returnPathMismatch) {
    score += 12;
    reasons.push(
      `The return-path belongs to ${mismatch.returnPathDomain}, which is different from the sender's domain.`
    );
  }

  technicalDetails.replyToDomain = mismatch.replyDomain || "not available";
  technicalDetails.returnPathDomain = mismatch.returnPathDomain || "not available";

  const linkAnalysis = detectLinkDeception(links, observedBrands);
  score += linkAnalysis.score;
  reasons.push(...linkAnalysis.findings);
  Object.assign(technicalDetails, linkAnalysis.technical);

  const fullText = `${subject} ${bodyText}`;

  const tfidfResult = classifyWithTfidf(fullText);
  let tfidfAnalysis: AnalysisResult["tfidfAnalysis"] = undefined;

  if (tfidfResult.totalTermsMatched > 0) {
    const tfidfContribution = Math.round(tfidfResult.phishingScore * 0.20);
    score += tfidfContribution;

    if (tfidfResult.phishingScore >= 40 && tfidfResult.topTerms.length > 0) {
      const topWords = tfidfResult.topTerms.slice(0, 5).map((t) => t.term);
      reasons.push(
        `TF-IDF text analysis detected high-frequency phishing indicators: ${topWords.join(", ")}.`
      );
    } else if (tfidfResult.phishingScore >= 15 && tfidfResult.topTerms.length > 0) {
      const topWords = tfidfResult.topTerms.slice(0, 3).map((t) => t.term);
      reasons.push(
        `Text analysis found some phishing-related terms: ${topWords.join(", ")}.`
      );
    }

    tfidfAnalysis = {
      phishingScore: tfidfResult.phishingScore,
      topTerms: tfidfResult.topTerms.slice(0, 8),
      totalTermsMatched: tfidfResult.totalTermsMatched,
    };

    technicalDetails.tfidfScore = String(tfidfResult.phishingScore);
    technicalDetails.tfidfTermsMatched = String(tfidfResult.totalTermsMatched);
  }

  const svmResult = classifyWithSvm(fullText);
  let svmAnalysis: AnalysisResult["svmAnalysis"] = undefined;

  if (svmResult.featureCount > 0) {
    const svmContribution = Math.round(svmResult.phishingProbability * 15);
    score += svmContribution;

    if (svmResult.phishingProbability >= 0.7) {
      reasons.push(
        `SVM classifier indicates high phishing probability (${Math.round(svmResult.phishingProbability * 100)}%).`
      );
    } else if (svmResult.phishingProbability >= 0.4) {
      reasons.push(
        `SVM classifier found moderate phishing signals (${Math.round(svmResult.phishingProbability * 100)}% probability).`
      );
    }

    svmAnalysis = {
      phishingProbability: svmResult.phishingProbability,
      confidence: svmResult.confidence,
      svmScore: svmResult.svmScore,
      topFeatures: svmResult.topFeatures.slice(0, 10),
      featureCount: svmResult.featureCount,
    };

    technicalDetails.svmProbability = `${Math.round(svmResult.phishingProbability * 100)}%`;
    technicalDetails.svmConfidence = `${Math.round(svmResult.confidence * 100)}%`;
  }

  let bertAnalysis: AnalysisResult["bertAnalysis"] = undefined;

  const realBertResult = await classifyWithRealBert(fullText);

  if (realBertResult) {
    const bertContribution = realBertResult.phishingProbability > 0.8
      ? Math.round(realBertResult.phishingProbability * 30)
      : realBertResult.phishingProbability > 0.6
        ? Math.round(realBertResult.phishingProbability * 20)
        : realBertResult.phishingProbability > 0.4
          ? Math.round(realBertResult.phishingProbability * 10)
          : 0;
    score += bertContribution;

    if (realBertResult.phishingProbability >= 0.7) {
      reasons.push(
        `DistilBERT deep learning model classifies this as phishing (${Math.round(realBertResult.phishingProbability * 100)}% confidence).`
      );
    } else if (realBertResult.phishingProbability >= 0.4) {
      reasons.push(
        `DistilBERT model detected moderate phishing characteristics (${Math.round(realBertResult.phishingProbability * 100)}% probability).`
      );
    }

    bertAnalysis = {
      phishingProbability: realBertResult.phishingProbability,
      confidence: realBertResult.confidence,
      modelVersion: realBertResult.modelVersion,
      modelSource: "real",
      label: realBertResult.label,
    };

    technicalDetails.bertProbability = `${Math.round(realBertResult.phishingProbability * 100)}%`;
    technicalDetails.bertConfidence = `${Math.round(realBertResult.confidence * 100)}%`;
    technicalDetails.bertModel = realBertResult.modelVersion;
    technicalDetails.bertSource = "real";
  } else {
    const bertResult = classifyWithBert(fullText);

    if (bertResult.tokenCount > 2) {
      const bertContribution = Math.round(bertResult.phishingProbability * 15);
      score += bertContribution;

      if (bertResult.phishingProbability >= 0.7) {
        reasons.push(
          `BERT simulated model classifies this as likely phishing (${Math.round(bertResult.phishingProbability * 100)}% confidence).`
        );
      } else if (bertResult.phishingProbability >= 0.4) {
        reasons.push(
          `BERT simulated model detected moderate phishing characteristics (${Math.round(bertResult.phishingProbability * 100)}% probability).`
        );
      }

      bertAnalysis = {
        phishingProbability: bertResult.phishingProbability,
        confidence: bertResult.confidence,
        tokenCount: bertResult.tokenCount,
        attentionInsights: bertResult.attentionInsights.slice(0, 8),
        modelVersion: bertResult.modelVersion,
        modelSource: "simulated",
      };

      technicalDetails.bertProbability = `${Math.round(bertResult.phishingProbability * 100)}%`;
      technicalDetails.bertConfidence = `${Math.round(bertResult.confidence * 100)}%`;
      technicalDetails.bertModel = bertResult.modelVersion;
      technicalDetails.bertSource = "simulated";
    }
  }

  score = Math.max(0, Math.min(100, score));

  const userActions: string[] = [];
  if (score >= 50) {
    userActions.push("Do not click links or open attachments in this email.");
    userActions.push("Verify the request using the company's real website or phone number.");
  } else if (score >= 25) {
    userActions.push("Be careful with links and verify the sender before taking action.");
  } else {
    userActions.push(
      "No strong phishing signal was found in the visible content, but keep normal caution."
    );
  }

  return {
    riskScore: score,
    verdict: verdictFromScore(score),
    confidence: confidenceFromScore(score),
    reasons: dedupe(reasons),
    userActions: dedupe(userActions),
    technicalDetails,
    headerAnalysis,
    tfidfAnalysis,
    svmAnalysis,
    bertAnalysis,
    impersonation,
    timeAnomaly,
  };
}
