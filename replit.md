# PhishGuard - Email Threat Analyzer

## Overview
PhishGuard is a Chrome extension + backend API for analyzing emails for phishing threats. The backend runs on Replit and provides the analysis API. The Chrome extension injects into Gmail and sends email data to the backend for analysis.

The web frontend serves as a landing page with a manual analysis tool and Chrome extension setup instructions.

## Architecture
- **Backend:** Express.js API running on Replit
- **Chrome Extension:** Content script for Gmail + popup for configuration
- **Web Frontend:** React landing page with manual analyzer + setup instructions
- **No database** - stateless analysis, results are not persisted

## Key Features
- TF-IDF text mining classifier for phishing language detection
- Full email header parsing (SPF, DKIM, DMARC verification)
- Heuristic-based content analysis (urgency, emotional pressure, sensitive info requests)
- Link deception detection (mismatched display text vs URL)
- Brand impersonation detection
- Attachment risk assessment
- Domain mismatch detection (reply-to, return-path vs sender)
- Received chain analysis (hop counting)
- Plain-English explanations of findings
- Risk scoring (0-100) with verdicts

## Detection Pipeline
1. Email text → tokenization → TF-IDF feature extraction → phishing language score
2. Heuristic pattern matching (urgency, emotional, sensitive info, platform abuse)
3. Header authentication analysis (SPF/DKIM/DMARC)
4. Link/domain analysis (deception, brand impersonation, domain mismatch)
5. Combined scoring → verdict + recommendations

## TF-IDF Classifier
- Pre-trained IDF weights from phishing email corpus (~100 phishing indicator terms)
- Multi-word phrase detection (e.g., "within 24 hours", "click here", "dear customer")
- Legitimate email damping terms (e.g., "unsubscribe", "privacy policy", "newsletter")
- TF-IDF contribution weighted at 35% of its score added to final risk score
- Located in `server/services/tfidfClassifier.ts`

## Project Structure
```
client/src/
  App.tsx                  - Main app layout with header + theme toggle
  components/
    theme-provider.tsx     - Dark/light theme context
    risk-gauge.tsx         - Visual risk score display
    analysis-result.tsx    - Full analysis result view with auth badges + TF-IDF display
  pages/
    dashboard.tsx          - Main page: manual analyzer + extension setup tabs

client/public/extension/   - Chrome extension files
  manifest.json            - Manifest V3
  content.js               - Gmail content script with TF-IDF result rendering
  content.css              - Side panel styling
  popup.html               - Extension popup with backend URL config

server/
  routes.ts                - POST /api/analyze-email, GET /api/health
  services/
    analyzeEmail.ts        - Main analysis orchestrator
    tfidfClassifier.ts     - TF-IDF text mining classifier
    headerParser.ts        - Full email header parsing (SPF/DKIM/DMARC)
    contentRules.ts        - Heuristic pattern matching
    reputation.ts          - Domain mismatch detection
    domains.ts             - URL/domain utility functions

shared/
  schema.ts                - EmailInput zod schema, AnalysisResult + TfidfDetail types
```

## API Endpoints
- `POST /api/analyze-email` - Analyze email data, returns risk score + findings + TF-IDF analysis
- `GET /api/health` - Health check

## Theme
- Cybersecurity-inspired teal/slate color palette
- Default dark mode
- Inter font family
