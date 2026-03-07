# GHOULPhishGuard - Email Threat Analyzer

## Overview
GHOULPhishGuard is a web-based email threat analyzer that checks emails for phishing indicators. Users paste email details and raw headers into the analyzer, and it returns a risk score with plain-English explanations.

The app includes educational pages: a usage guide (how to extract email headers), a phishing awareness guide for non-technical users, and a detection techniques page explaining the methods used.

## Architecture
- **Backend:** Express.js API running on Replit
- **Frontend:** React multi-page app with wouter routing
- **Real ML Model:** DistilBERT phishing classifier (ONNX INT8 quantized, ~64MB) loaded via @huggingface/transformers
- **No database** - stateless analysis, results are not persisted
- **No external API calls** - all analysis runs locally in-process (model downloaded once, cached on disk)

## Security
- **Helmet** security headers (CSP, X-Frame-Options, MIME sniffing, etc.)
- **Rate limiting** on analysis endpoint (20 req/min per IP via express-rate-limit)
- **Input validation** with Zod schemas + field-level max lengths
- **Request body size limit** (500kb)
- **CORS** restricted when ALLOWED_ORIGINS env var is set (comma-separated)
- **LOCAL_ONLY mode** when LOCAL_ONLY=true env var is set (restricts API to localhost)
- **No user content in logs** - only method/path/status/duration logged
- **No data retention** - input → analysis → result → discard
- **Content sanitization** on rendered output via sanitizePlain utility
- **No dangerouslySetInnerHTML** in application code
- **No URL fetching** - no SSRF risk (analysis is purely text-based)
- **Risk disclaimer** shown on analyzer page

## Environment Variables
- `LOCAL_ONLY` - Set to "true" to restrict API to localhost connections only
- `ALLOWED_ORIGINS` - Comma-separated list of allowed CORS origins (e.g., "https://example.com,https://app.example.com")
- `SESSION_SECRET` - Session secret (available in secrets)

## Key Features
- **ML Ensemble** — three classifiers combined:
  - TF-IDF keyword analysis (107 phishing terms + 13 damper terms)
  - TF-IDF + Linear SVM (150-feature vocabulary + bigram features + pre-trained weights)
  - **Real DistilBERT** (cybersectony/phishing-email-detection-distilbert_v2.4.1, ONNX via @huggingface/transformers, up to 30 pts)
  - Simulated BERT fallback (phishbert-v1-distilled, used when real model is loading/unavailable, up to 15 pts)
- Domain impersonation detection (Levenshtein distance typosquatting + homoglyph look-alike characters)
- Full email header parsing (SPF, DKIM, DMARC verification)
- Time-of-day anomaly detection (unusual send times)
- Heuristic-based content analysis (urgency, emotional pressure, sensitive info requests)
- Link deception detection (mismatched display text vs URL)
- Brand impersonation detection in URLs
- Attachment risk assessment
- Domain mismatch detection (reply-to, return-path vs sender)
- Received chain analysis (hop counting)
- Plain-English explanations of findings
- Risk scoring (0-100) with verdicts

## Pages
- **/** - Email Analyzer (main tool)
- **/how-to-use** - Instructions on extracting email headers from Gmail, Outlook, Yahoo, Apple Mail, Thunderbird
- **/awareness** - Phishing awareness guide for non-technical users with real examples
- **/techniques** - Explanation of all detection techniques used (TF-IDF, Levenshtein, SPF/DKIM/DMARC, etc.)

## Project Structure
```
client/src/
  App.tsx                  - Navigation layout with wouter routing (4 pages)
  lib/
    sanitize.ts            - Content sanitization utility (sanitizePlain)
  components/
    theme-provider.tsx     - Dark/light theme context
    risk-gauge.tsx         - Visual risk score display
    analysis-result.tsx    - Full result view with impersonation/time/auth/TF-IDF cards
  pages/
    dashboard.tsx          - Email analyzer form + results + disclaimer
    how-to-use.tsx         - Instructions for getting email data/headers
    awareness.tsx          - Phishing awareness guide
    techniques.tsx         - Detection techniques explained

server/
  index.ts                 - Express setup, sanitized logging (metadata only)
  routes.ts                - POST /api/analyze-email, GET /api/health, helmet, rate limiting, CORS, local-only guard
  services/
    analyzeEmail.ts        - Main analysis orchestrator (ensemble scoring)
    domainImpersonation.ts - Levenshtein + homoglyph + brand detection
    tfidfClassifier.ts     - TF-IDF text mining classifier
    svmClassifier.ts       - TF-IDF + Linear SVM with pre-trained weights (150 features + bigrams)
    realBertClassifier.ts  - Real DistilBERT classifier via @huggingface/transformers (ONNX INT8, lazy-loaded, cached)
    bertClassifier.ts      - Simulated BERT fallback (subword tokenization, self-attention, classification head)
    timeAnomaly.ts         - Time-of-day anomaly detection
    headerParser.ts        - Full email header parsing (SPF/DKIM/DMARC)
    contentRules.ts        - Heuristic pattern matching
    reputation.ts          - Domain mismatch detection
    domains.ts             - URL/domain utility functions

shared/
  schema.ts                - EmailInput schema (with field-level size limits), AnalysisResult types
```

## API Endpoints
- `POST /api/analyze-email` - Full analysis with all detection modules (rate-limited, local-only guard)
- `GET /api/health` - Health check

## Theme
- Cybersecurity-inspired teal/slate color palette
- Default dark mode
- Inter font family
