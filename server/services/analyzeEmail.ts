import { analyzeContent } from "./contentRules";
import { extractLinksFromText, findDomainMismatch, mergeLinks } from "./reputation";
import { safeUrl, getDomainFromEmail, getBaseDomain } from "./domains";
import { parseEmailHeaders, headerAuthFindings, hasRealAuthHeaders } from "./headerParser";
import { classifyWithTfidf } from "./tfidfClassifier";
import { classifyWithSvm } from "./svmClassifier";
import { classifyWithBert } from "./bertClassifier";
import { classifyWithRealBert } from "./realBertClassifier";
import { detectDomainImpersonation } from "./domainImpersonation";
import { detectTimeAnomaly, extractDateFromHeaders } from "./timeAnomaly";
import { checkUrlReputation } from "./urlReputation";
import { analyzeThreatIntel } from "./threatIntel";
import { analyzeMailInfrastructure } from "./mailInfrastructure";
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

function areDomainsAligned(left: string, right: string): boolean | undefined {
  if (!left || !right) return undefined;
  return getBaseDomain(left) === getBaseDomain(right);
}

function hasStrongAuthPass(headerAnalysis: AnalysisResult["headerAnalysis"]): boolean {
  return !!headerAnalysis?.headersParsed
    && headerAnalysis.spf.status === "pass"
    && headerAnalysis.dkim.status === "pass"
    && headerAnalysis.dmarc.status === "pass";
}

function getBaseBertContribution(
  probability: number,
  modelSource: "real" | "simulated",
): number {
  if (modelSource === "real") {
    if (probability > 0.8) return Math.round(probability * 30);
    if (probability > 0.6) return Math.round(probability * 20);
    if (probability > 0.4) return Math.round(probability * 10);
    return 0;
  }

  if (probability >= 0.7) return Math.round(probability * 15);
  if (probability >= 0.4) return Math.round(probability * 8);
  return 0;
}

function calibrateBertContribution(
  probability: number,
  modelSource: "real" | "simulated",
  nonBertScore: number,
  strongAuthPass: boolean,
): { contribution: number; baseContribution: number; calibration: string } {
  const baseContribution = getBaseBertContribution(probability, modelSource);
  if (baseContribution === 0) {
    return { contribution: 0, baseContribution, calibration: "not_applied" };
  }

  if (strongAuthPass && nonBertScore < 10) {
    return {
      contribution: Math.min(baseContribution, 6),
      baseContribution,
      calibration: "downweighted_clean_auth_low_corroboration",
    };
  }

  if (strongAuthPass && nonBertScore < 20) {
    return {
      contribution: Math.min(baseContribution, 10),
      baseContribution,
      calibration: "downweighted_clean_auth_mixed_signals",
    };
  }

  if (nonBertScore < 15) {
    return {
      contribution: Math.min(baseContribution, 8),
      baseContribution,
      calibration: "downweighted_low_corroboration",
    };
  }

  if (nonBertScore < 30) {
    return {
      contribution: Math.min(baseContribution, Math.max(10, Math.round(baseContribution * 0.6))),
      baseContribution,
      calibration: "moderated_partial_corroboration",
    };
  }

  return {
    contribution: baseContribution,
    baseContribution,
    calibration: "full_weight",
  };
}

export async function analyzeEmail(email: EmailInput): Promise<AnalysisResult> {
  const bodyText = email.bodyText || "";
  const subject = email.subject || "";
  const rawHeaders = email.rawHeaders || "";
  const inputSenderIdentity = email.fromEmail || "";
  let fromEmail = (email.fromEmail || "").toLowerCase();
  let replyTo = (email.replyTo || "").toLowerCase();
  let returnPath = (email.returnPath || "").toLowerCase();
  const attachments = email.attachments || [];
  const userProvidedLinks = email.links || [];
  const detectedLinks = extractLinksFromText(bodyText);
  const links = mergeLinks(userProvidedLinks, detectedLinks);
  const observedBrands = email.observedBrandDomains || [];

  let score = 0;
  const reasons: string[] = [];
  let headerAnalysis: AnalysisResult["headerAnalysis"] = undefined;
  let infrastructureAnalysis: AnalysisResult["infrastructureAnalysis"] = undefined;
  const parsedHeaders = rawHeaders ? parseEmailHeaders(rawHeaders) : null;

  if (parsedHeaders) {
    if (!fromEmail && parsedHeaders.from) fromEmail = parsedHeaders.from.toLowerCase();
    if (!replyTo && parsedHeaders.replyTo) replyTo = parsedHeaders.replyTo.toLowerCase();
    if (!returnPath && parsedHeaders.returnPath) returnPath = parsedHeaders.returnPath.toLowerCase();
  }

  if (parsedHeaders && (hasRealAuthHeaders(rawHeaders) || parsedHeaders.receivedChain.length > 0 || !!parsedHeaders.sourceIp)) {
    headerAnalysis = {
      spf: parsedHeaders.spf,
      dkim: parsedHeaders.dkim,
      dmarc: parsedHeaders.dmarc,
      receivedHops: parsedHeaders.receivedChain.length,
      headersParsed: true,
      spfMailFrom: parsedHeaders.spfMailFrom || undefined,
      spfAligned: areDomainsAligned(parsedHeaders.spfMailFrom, getDomainFromEmail(parsedHeaders.from)),
      dkimDomain: parsedHeaders.dkimDomain || undefined,
      dkimSelector: parsedHeaders.dkimSelector || undefined,
      dkimAligned: areDomainsAligned(parsedHeaders.dkimDomain, getDomainFromEmail(parsedHeaders.from)),
      dmarcHeaderFrom: parsedHeaders.dmarcHeaderFrom || undefined,
      dmarcAligned: areDomainsAligned(parsedHeaders.dmarcHeaderFrom, getDomainFromEmail(parsedHeaders.from)),
      sourceIp: parsedHeaders.sourceIp || null,
      sourceHost: parsedHeaders.sourceHost || null,
    };
  }

  if (parsedHeaders && hasRealAuthHeaders(rawHeaders)) {
    const authFindings = headerAuthFindings(parsedHeaders);
    score += authFindings.score;
    reasons.push(...authFindings.findings);
  }

  const senderBaseDomain = getBaseDomain(getDomainFromEmail(fromEmail));

  const technicalDetails: Record<string, string> = {
    sender: fromEmail || "unknown",
    subject: subject || "none",
    linksFound: String(links.length),
    attachmentsFound: String(attachments.length),
    senderDomain: senderBaseDomain || "unknown",
  };
  if (detectedLinks.length > 0) {
    technicalDetails.bodyLinksExtracted = String(detectedLinks.length);
  }

  if (parsedHeaders) {
    if (parsedHeaders.spfMailFrom) technicalDetails.spfMailFrom = parsedHeaders.spfMailFrom;
    if (parsedHeaders.dkimDomain) technicalDetails.dkimDomain = parsedHeaders.dkimDomain;
    if (parsedHeaders.dkimSelector) technicalDetails.dkimSelector = parsedHeaders.dkimSelector;
    if (parsedHeaders.dmarcHeaderFrom) technicalDetails.dmarcHeaderFrom = parsedHeaders.dmarcHeaderFrom;
    if (parsedHeaders.sourceIp) technicalDetails.sourceIp = parsedHeaders.sourceIp;
    if (parsedHeaders.sourceHost) technicalDetails.sourceHost = parsedHeaders.sourceHost;
  }

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

  const senderIdentity = (inputSenderIdentity || parsedHeaders?.fromRaw || fromEmail).toLowerCase();
  const contentAnalysis = analyzeContent(bodyText, subject, links, senderIdentity);
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

  if (parsedHeaders && (parsedHeaders.sourceIp || parsedHeaders.sourceHost)) {
    infrastructureAnalysis = analyzeMailInfrastructure({
      sourceIp: parsedHeaders.sourceIp,
      sourceHost: parsedHeaders.sourceHost,
      fromDomain: senderBaseDomain,
      dkimDomain: parsedHeaders.dkimDomain,
      spfMailFrom: parsedHeaders.spfMailFrom,
      dmarcHeaderFrom: parsedHeaders.dmarcHeaderFrom,
      spfStatus: parsedHeaders.spf.status,
      dkimStatus: parsedHeaders.dkim.status,
      dmarcStatus: parsedHeaders.dmarc.status,
    });

    score += infrastructureAnalysis.score;
    reasons.push(...infrastructureAnalysis.findings);
    technicalDetails.infrastructureProvider = infrastructureAnalysis.detectedProvider;
    technicalDetails.infrastructureIpType = infrastructureAnalysis.ipType;
    if (infrastructureAnalysis.expectedProvider) {
      technicalDetails.infrastructureExpectedProvider = infrastructureAnalysis.expectedProvider;
    }
    if (infrastructureAnalysis.matchedRange) {
      technicalDetails.infrastructureRange = infrastructureAnalysis.matchedRange;
    }
    technicalDetails.infrastructureAlignment = infrastructureAnalysis.alignment;
  }

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

  const allDomains: string[] = [];
  const allUrls: string[] = [];

  if (senderBaseDomain) allDomains.push(senderBaseDomain);
  for (const link of links) {
    const parsed = safeUrl(link.href);
    if (parsed) {
      allDomains.push(getBaseDomain(parsed.hostname));
      allUrls.push(link.href);
    }
  }

  let urlReputation: AnalysisResult["urlReputation"] = undefined;
  let threatIntel: AnalysisResult["threatIntel"] = undefined;

  const uniqueDomains = Array.from(new Set(allDomains.filter(Boolean)));

  const [urlRepResults, threatIntelResult] = await Promise.all([
    Promise.all(uniqueDomains.slice(0, 3).map((d) => checkUrlReputation(d))),
    analyzeThreatIntel(uniqueDomains, allUrls),
  ]);

  let bestUrlRep = urlRepResults[0] || null;
  for (const rep of urlRepResults) {
    if (rep.totalScore > (bestUrlRep?.totalScore || 0)) {
      bestUrlRep = rep;
    }
  }

  if (bestUrlRep && bestUrlRep.totalScore > 0) {
    const urlRepContribution = Math.min(bestUrlRep.totalScore, 20);
    score += urlRepContribution;
    reasons.push(...bestUrlRep.findings);
    Object.assign(technicalDetails, bestUrlRep.technical);
    urlReputation = bestUrlRep;
    technicalDetails.urlReputationScore = String(bestUrlRep.totalScore);
  } else if (bestUrlRep) {
    urlReputation = bestUrlRep;
  }

  if (threatIntelResult.score > 0) {
    const threatContribution = Math.min(threatIntelResult.score, 25);
    score += threatContribution;
    reasons.push(...threatIntelResult.findings);
    threatIntel = threatIntelResult;
    technicalDetails.threatIntelScore = String(threatIntelResult.score);
    technicalDetails.domainEntropy = String(threatIntelResult.domainEntropy);
    if (threatIntelResult.matchedIndicators.length > 0) {
      technicalDetails.threatIndicators = threatIntelResult.matchedIndicators.join(", ");
    }
  } else {
    threatIntel = threatIntelResult;
  }

  if (bertAnalysis) {
    const nonBertScore = score;
    const strongAuthPass = hasStrongAuthPass(headerAnalysis);
    const bertCalibration = calibrateBertContribution(
      bertAnalysis.phishingProbability,
      bertAnalysis.modelSource,
      nonBertScore,
      strongAuthPass,
    );

    score += bertCalibration.contribution;
    technicalDetails.bertContribution = String(bertCalibration.contribution);
    if (bertCalibration.calibration !== "full_weight" && bertCalibration.calibration !== "not_applied") {
      technicalDetails.bertCalibration = bertCalibration.calibration;
    }

    if (bertCalibration.contribution >= 8) {
      if (bertCalibration.contribution < bertCalibration.baseContribution && strongAuthPass && nonBertScore < 20) {
        reasons.push(
          `DistilBERT flagged phishing-like wording, but sender authentication was clean and corroborating risk signals were limited.`
        );
      } else if (bertCalibration.contribution < bertCalibration.baseContribution && nonBertScore < 30) {
        reasons.push(
          `DistilBERT detected phishing-like wording, but the ensemble only found partial corroboration.`
        );
      } else if (bertAnalysis.phishingProbability >= 0.7) {
        reasons.push(
          `${bertAnalysis.modelSource === "real" ? "DistilBERT deep learning model" : "BERT simulated model"} classifies this as phishing (${Math.round(bertAnalysis.phishingProbability * 100)}% confidence).`
        );
      } else if (bertAnalysis.phishingProbability >= 0.4) {
        reasons.push(
          `${bertAnalysis.modelSource === "real" ? "DistilBERT model" : "BERT simulated model"} detected moderate phishing characteristics (${Math.round(bertAnalysis.phishingProbability * 100)}% probability).`
        );
      }
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
    urlReputation,
    threatIntel,
    infrastructureAnalysis,
  };
}
