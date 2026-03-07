# PhishGuard - Email Threat Analyzer

## Overview
PhishGuard is a web-based email threat analyzer that checks emails for phishing indicators. Users paste email details and raw headers into the analyzer, and it returns a risk score with plain-English explanations.

The app includes educational pages: a usage guide (how to extract email headers), a phishing awareness guide for non-technical users, and a detection techniques page explaining the methods used.

## Architecture
- **Backend:** Express.js API running on Replit
- **Frontend:** React multi-page app with wouter routing
- **No database** - stateless analysis, results are not persisted

## Key Features
- Domain impersonation detection (Levenshtein distance typosquatting + homoglyph look-alike characters)
- TF-IDF text mining classifier for phishing language detection
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
  components/
    theme-provider.tsx     - Dark/light theme context
    risk-gauge.tsx         - Visual risk score display
    analysis-result.tsx    - Full result view with impersonation/time/auth/TF-IDF cards
  pages/
    dashboard.tsx          - Email analyzer form + results
    how-to-use.tsx         - Instructions for getting email data/headers
    awareness.tsx          - Phishing awareness guide
    techniques.tsx         - Detection techniques explained

server/
  routes.ts                - POST /api/analyze-email, GET /api/health
  services/
    analyzeEmail.ts        - Main analysis orchestrator
    domainImpersonation.ts - Levenshtein + homoglyph + brand detection
    tfidfClassifier.ts     - TF-IDF text mining classifier
    timeAnomaly.ts         - Time-of-day anomaly detection
    headerParser.ts        - Full email header parsing (SPF/DKIM/DMARC)
    contentRules.ts        - Heuristic pattern matching
    reputation.ts          - Domain mismatch detection
    domains.ts             - URL/domain utility functions

shared/
  schema.ts                - EmailInput schema, AnalysisResult + all detail types
```

## API Endpoints
- `POST /api/analyze-email` - Full analysis with all detection modules
- `GET /api/health` - Health check

## Theme
- Cybersecurity-inspired teal/slate color palette
- Default dark mode
- Inter font family
