import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import {
  Cpu,
  Globe,
  Brain,
  ShieldCheck,
  Link as LinkIcon,
  Paperclip,
  Clock,
  Mail,
  FileText,
  ArrowRight,
  BarChart3,
  Zap,
  Layers,
  Search,
  Database,
  Server,
} from "lucide-react";

export default function Techniques() {
  return (
    <div className="max-w-3xl mx-auto p-4 sm:p-6 space-y-8">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-3" data-testid="heading-techniques">
          <Cpu className="w-6 h-6 text-primary" />
          Detection Techniques
        </h1>
        <p className="text-muted-foreground">
          This page describes the techniques currently implemented in GHOULPhishGuard. The analyzer combines
          rule-based checks, header parsing, URL reputation, and multiple text classifiers into one score.
        </p>
      </div>

      <Card className="bg-muted/50">
        <CardContent className="pt-4">
          <h3 className="text-sm font-medium mb-3">How the Scoring Works</h3>
          <p className="text-xs text-muted-foreground leading-relaxed">
            Each technique contributes risk points. The final score is clamped to 0-100 and then mapped to a verdict.
            DistilBERT is also calibrated against the rest of the evidence, so a single aggressive ML score does not
            automatically override clean authentication and weak corroboration.
          </p>
          <div className="grid grid-cols-4 gap-2 mt-4">
            <div className="text-center p-2 rounded bg-emerald-500/10">
              <p className="text-lg font-bold text-emerald-500">0-24</p>
              <p className="text-xs text-muted-foreground">Low Risk</p>
            </div>
            <div className="text-center p-2 rounded bg-yellow-500/10">
              <p className="text-lg font-bold text-yellow-500">25-49</p>
              <p className="text-xs text-muted-foreground">Suspicious</p>
            </div>
            <div className="text-center p-2 rounded bg-orange-500/10">
              <p className="text-lg font-bold text-orange-500">50-74</p>
              <p className="text-xs text-muted-foreground">High Risk</p>
            </div>
            <div className="text-center p-2 rounded bg-red-500/10">
              <p className="text-lg font-bold text-red-500">75-100</p>
              <p className="text-xs text-muted-foreground">Likely Phishing</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="space-y-5">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Brain className="w-5 h-5 text-primary" />
              1. TF-IDF Keyword Scoring
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              The first text layer is a handcrafted TF-IDF scorer. It uses a phishing-focused term dictionary with
              weighted single words and multi-word phrases, then lowers the score when legitimate newsletter markers
              such as unsubscribe language are present.
            </p>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-medium mb-1">What it looks for</p>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {["verify", "urgent", "credential", "wire transfer", "within 24 hours", "click here", "microsoft account", "social security"].map((term) => (
                  <span key={term} className="px-2 py-0.5 rounded bg-muted text-xs font-mono">{term}</span>
                ))}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              This is not a live-trained pipeline inside the app. The weights are embedded in the code so the result is
              deterministic and fast.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 20 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Zap className="w-5 h-5 text-primary" />
              2. Linear SVM-Style Scorer
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              The second text layer is a fixed-vocabulary linear scorer inspired by a TF-IDF plus linear SVM pipeline.
              The app embeds per-term IDF values, feature weights, a bias term, and extra bigram boosts, then converts
              the final decision score into a probability with a sigmoid.
            </p>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-mono text-muted-foreground mb-2">decision = dot(tfidf, weights) + bias + bigram_boost</p>
              <div className="flex flex-wrap gap-1.5">
                {["account suspended", "verify identity", "wire transfer", "enable macros", "unusual activity", "security alert"].map((term) => (
                  <span key={term} className="px-2 py-0.5 rounded bg-red-500/10 text-red-600 text-xs font-mono">{term}</span>
                ))}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              It also includes negative features such as privacy-policy or unsubscribe-style language, so the score is
              less likely to spike on routine newsletters.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 15 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Brain className="w-5 h-5 text-primary" />
              3. DistilBERT Text Classifier
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              The deep-learning layer uses a real ONNX DistilBERT phishing model loaded locally through
              <span className="font-mono"> @huggingface/transformers</span>. The current model source is
              <span className="font-mono"> onnx-community/phishing-email-detection-distilbert_v2.4.1-ONNX</span>.
            </p>
            <div className="bg-emerald-500/10 rounded-md p-3">
              <p className="text-xs font-medium text-emerald-700 mb-1">How the output is used</p>
              <p className="text-xs text-muted-foreground">
                The analyzer sums the phishing-like labels returned by the model, caches the result, and exposes the top
                label and probability in the UI. If the real model is unavailable, the app falls back to the simulated
                BERT path so analysis still completes.
              </p>
            </div>
            <p className="text-xs text-muted-foreground">
              DistilBERT is powerful but aggressive, so the ensemble downweights it when authentication is clean and the
              rest of the evidence is weak.
            </p>
            <p className="text-xs text-muted-foreground font-medium">
              Contribution: up to 30 points before calibration, or up to 15 points for the simulated fallback
            </p>
          </CardContent>
        </Card>

        <Card className="bg-muted/50">
          <CardContent className="pt-4">
            <div className="flex items-start gap-3">
              <Layers className="w-5 h-5 text-primary mt-0.5 shrink-0" />
              <div>
                <p className="text-sm font-medium mb-2">Ensemble Calibration</p>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  The three ML layers run independently, but the final score is not a blind sum. DistilBERT is
                  moderated when SPF, DKIM, and DMARC all pass and the non-BERT evidence stays weak. That reduces false
                  positives on benign newsletters, receipts, and routine account messages.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Globe className="w-5 h-5 text-primary" />
              4. Domain Impersonation Detection
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              The sender domain is checked against a brand list and alias list. The implementation looks for close
              spellings, look-alike characters, explicit brand names inside fake domains, and keyword matches tied to
              known companies.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Typosquatting</p>
                <p className="text-xs text-muted-foreground">Levenshtein distance of 1-2 from a tracked brand label.</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Homoglyphs</p>
                <p className="text-xs text-muted-foreground">Patterns like 0 for o, rn for m, or vv for w.</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Brand in fake domain</p>
                <p className="text-xs text-muted-foreground">Examples: microsoft-alert-check.com or paypal-login-verify.com.</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Brand keyword match</p>
                <p className="text-xs text-muted-foreground">Brand terms tied to 30+ tracked companies and services.</p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground font-medium">Contribution: 20-30 points depending on the match type</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-primary" />
              5. Email Authentication and Alignment
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              When raw headers are present, the analyzer parses <span className="font-mono">Authentication-Results</span>,
              <span className="font-mono"> Received-SPF</span>, and <span className="font-mono"> Received</span> headers.
              It does more than pass or fail badges: it also extracts the domains behind SPF, DKIM, and DMARC and checks
              whether they align with the visible From domain.
            </p>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-medium mb-1">Parsed fields</p>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {["spf=smtp.mailfrom", "dkim=header.d", "dkim=header.s", "dmarc=header.from", "Received hop count"].map((term) => (
                  <span key={term} className="px-2 py-0.5 rounded bg-muted text-xs font-mono">{term}</span>
                ))}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              SPF fail adds 20 points, DKIM fail adds 15, and DMARC fail adds 20. Additional points can be added for
              alignment oddities and for unusually long relay chains.
            </p>
            <p className="text-xs text-muted-foreground font-medium">
              Typical failure contribution: up to 55 points, with extra alignment and hop penalties in unusual cases
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Server className="w-5 h-5 text-primary" />
              6. Mail Infrastructure and IP Range Matching
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              The analyzer extracts the earliest source IP from <span className="font-mono">client-ip</span> in
              <span className="font-mono"> Received-SPF</span> or from the earliest Received hop. It then classifies the
              IP type and checks whether the host or address matches known outbound mail infrastructure.
            </p>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-medium mb-1">Current provider mappings</p>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {["Microsoft 365", "Google Workspace", "Amazon SES", "SendGrid", "Mailchimp"].map((provider) => (
                  <span key={provider} className="px-2 py-0.5 rounded bg-muted text-xs font-mono">{provider}</span>
                ))}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              If a message claims to be from a Microsoft 365 sender but the earliest infrastructure matches Google
              Workspace, the mismatch is surfaced as a finding. Private, loopback, reserved, link-local, and similar IP
              types are also flagged when they appear as the earliest external source.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 18 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <LinkIcon className="w-5 h-5 text-primary" />
              7. Link Extraction and Deception Checks
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Links are not limited to the manual input fields. The analyzer automatically extracts http, https, and
              www-style links from the pasted body text and merges them with any explicitly provided links before scoring.
            </p>
            <div className="bg-muted rounded-md p-3 text-xs font-mono space-y-1">
              <p className="text-muted-foreground">Displayed: <span className="text-emerald-500">https://paypal.com/verify</span></p>
              <p className="text-muted-foreground">Actual: <span className="text-red-500">https://paypal-login-safe-check.com/verify</span></p>
            </div>
            <p className="text-xs text-muted-foreground">
              A visible URL that does not match its actual destination adds risk. When brand context is available, links
              that include a brand name but resolve to a different base domain can add even more.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: 15-40 points depending on the mismatch</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <FileText className="w-5 h-5 text-primary" />
              8. Content Pattern Rules
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Separate from the ML models, the analyzer applies rule-based pattern checks to the subject, body, and link
              text. These rules are simple, explainable, and useful even when the message is too short for the ML layers
              to be confident.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Urgency (+10)</p>
                <p className="text-xs text-muted-foreground">urgent, immediately, action required, final warning</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Emotional pressure (+8)</p>
                <p className="text-xs text-muted-foreground">security alert, unusual login, account compromised</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Sensitive requests (+12)</p>
                <p className="text-xs text-muted-foreground">password, SSN, bank account, verification code</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Abused platforms (+8)</p>
                <p className="text-xs text-muted-foreground">Google Forms, Google Sites, SharePoint, Notion, Dropbox</p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 38 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Mail className="w-5 h-5 text-primary" />
              9. Sender, Reply-To, and Return-Path Mismatch
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              The analyzer compares the base domain of the visible From address with the Reply-To and Return-Path
              addresses. Phishing messages often ask users to trust one identity while replies or bounces route to
              another domain.
            </p>
            <div className="bg-muted rounded-md p-3 text-xs font-mono space-y-1">
              <p className="text-muted-foreground">From: <span className="text-foreground">security@paypal.com</span></p>
              <p className="text-muted-foreground">Reply-To: <span className="text-red-500">support@paypal-reset-check.com</span></p>
              <p className="text-muted-foreground">Return-Path: <span className="text-red-500">mailer@other-domain.org</span></p>
            </div>
            <p className="text-xs text-muted-foreground">
              This is a useful signal, but not proof by itself. Some legitimate senders do use separate bounce
              infrastructure, which is why it should be interpreted together with SPF, DKIM, DMARC, and infrastructure
              findings.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 32 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Paperclip className="w-5 h-5 text-primary" />
              10. Attachment Risk Checks
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              The analyzer flags attachment extensions commonly used in phishing and malware delivery.
            </p>
            <div className="flex flex-wrap gap-1.5 mt-1">
              {[".zip", ".exe", ".js", ".iso", ".html", ".docm", ".xlsm", ".scr"].map((ext) => (
                <span key={ext} className="px-2 py-0.5 rounded bg-red-500/10 text-red-600 text-xs font-mono">{ext}</span>
              ))}
            </div>
            <p className="text-xs text-muted-foreground font-medium">Contribution: 12 points when risky attachments are present</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Clock className="w-5 h-5 text-primary" />
              11. Time-of-Day Anomaly Detection
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              If a valid Date header is available, the analyzer checks the UTC send time. Messages sent between 01:00
              and 05:00 UTC are flagged as unusual, and late-night weekend mail is treated as an even stronger signal.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: 8 points for unusual hours, or 10 points for weekend late-night patterns</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Search className="w-5 h-5 text-primary" />
              12. URL Reputation and Domain Age
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              For up to three relevant domains, the analyzer performs an RDAP lookup through
              <span className="font-mono"> rdap.org</span> and checks whether the domain is newly registered, uses a
              high-risk TLD, or sits on a free hosting platform.
            </p>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-medium mb-1">Age scoring</p>
              <ul className="text-xs text-muted-foreground space-y-1">
                <li><span className="font-medium text-red-500">&lt; 7 days</span> - 15 points</li>
                <li><span className="font-medium text-orange-500">&lt; 30 days</span> - 10 points</li>
                <li><span className="font-medium text-amber-500">&lt; 90 days</span> - 5 points</li>
              </ul>
            </div>
            <p className="text-xs text-muted-foreground">
              TLD risk adds 8 points and free hosting adds 6. If RDAP is unavailable, analysis continues without age
              data rather than failing the request.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 20 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Database className="w-5 h-5 text-primary" />
              13. Threat Intel Heuristics
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              The threat-intel layer uses local heuristics on domains and URLs, plus optional Google Safe Browsing
              checks for up to three hosts. It is not a full commercial intel feed, but it catches a broad set of
              suspicious domain traits.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Entropy and naming patterns</p>
                <p className="text-xs text-muted-foreground">High-entropy names, phishing keyword patterns, excessive subdomains</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Infrastructure clues</p>
                <p className="text-xs text-muted-foreground">Shorteners, raw IP URLs, free-hosting platforms, suspicious TLDs</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Homograph checks</p>
                <p className="text-xs text-muted-foreground">Non-ASCII and xn-- domains that can mimic trusted brands</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Safe Browsing</p>
                <p className="text-xs text-muted-foreground">Optional Google Transparency lookup for dangerous-site signals</p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              The raw threat score can exceed the final contribution. In the final ensemble, this layer is capped before
              being added to the overall risk score.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Effective contribution: up to 25 points in the final score</p>
          </CardContent>
        </Card>
      </div>

      <div className="flex justify-center gap-3">
        <Link href="/">
          <Button data-testid="button-go-analyze-from-techniques">
            <ArrowRight className="w-4 h-4 mr-2" />
            Try the Analyzer
          </Button>
        </Link>
        <Link href="/awareness">
          <Button variant="outline" data-testid="button-go-awareness">
            Phishing Awareness Guide
          </Button>
        </Link>
      </div>
    </div>
  );
}
