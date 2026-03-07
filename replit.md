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
- Full email header parsing (SPF, DKIM, DMARC verification)
- Heuristic-based content analysis (urgency, emotional pressure, sensitive info requests)
- Link deception detection (mismatched display text vs URL)
- Brand impersonation detection
- Attachment risk assessment
- Domain mismatch detection (reply-to, return-path vs sender)
- Received chain analysis (hop counting)
- Plain-English explanations of findings
- Risk scoring (0-100) with verdicts

## Project Structure
```
client/src/
  App.tsx                  - Main app layout with header + theme toggle
  components/
    theme-provider.tsx     - Dark/light theme context
    risk-gauge.tsx         - Visual risk score display
    analysis-result.tsx    - Full analysis result view with auth badges
  pages/
    dashboard.tsx          - Main page: manual analyzer + extension setup tabs

client/public/extension/   - Chrome extension files
  manifest.json            - Manifest V3
  content.js               - Gmail content script
  content.css              - Side panel styling
  popup.html               - Extension popup with backend URL config

server/
  routes.ts                - POST /api/analyze-email, GET /api/health
  services/
    analyzeEmail.ts        - Main analysis orchestrator
    headerParser.ts        - Full email header parsing (SPF/DKIM/DMARC)
    contentRules.ts        - Heuristic pattern matching
    reputation.ts          - Domain mismatch detection
    domains.ts             - URL/domain utility functions

shared/
  schema.ts                - EmailInput zod schema, AnalysisResult type
```

## API Endpoints
- `POST /api/analyze-email` - Analyze email data, returns risk score + findings
- `GET /api/health` - Health check

## Theme
- Cybersecurity-inspired teal/slate color palette
- Default dark mode
- Inter font family
