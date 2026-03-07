import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import {
  Cpu,
  Globe,
  Brain,
  ShieldCheck,
  LinkIcon,
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
          GHOULPhishGuard uses multiple layers of analysis to detect phishing emails. Here is how each technique works and what it catches.
        </p>
      </div>

      <Card className="bg-muted/50">
        <CardContent className="pt-4">
          <h3 className="text-sm font-medium mb-3">How the Scoring Works</h3>
          <p className="text-xs text-muted-foreground leading-relaxed">
            Each detection technique contributes points to the overall risk score (0 to 100). Multiple signals combined produce a more confident result. A single signal alone might only flag the email as "suspicious," but several signals together can confirm it as "likely phishing."
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
              1. TF-IDF Text Mining
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              TF-IDF (Term Frequency - Inverse Document Frequency) is a text mining technique that measures how important a word is in a document compared to a larger collection of documents. We use it to detect phishing-specific language patterns.
            </p>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-mono text-muted-foreground mb-2">How it works:</p>
              <p className="text-xs font-mono">tf-idf(term) = tf(term) x idf(term)</p>
              <ul className="text-xs text-muted-foreground mt-2 space-y-1">
                <li><span className="font-medium text-foreground">TF (Term Frequency)</span> — how often a word appears in the email</li>
                <li><span className="font-medium text-foreground">IDF (Inverse Document Frequency)</span> — how unique that word is across all emails (rare words in phishing get higher weight)</li>
              </ul>
            </div>
            <div>
              <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                <BarChart3 className="w-3 h-3" />
                Example high-IDF phishing words:
              </p>
              <div className="flex flex-wrap gap-1.5">
                {["verify", "urgent", "suspended", "credentials", "unauthorized", "compromised", "click here", "within 24 hours", "act now", "dear customer"].map((term) => (
                  <span key={term} className="px-2 py-0.5 rounded bg-muted text-xs font-mono">{term}</span>
                ))}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              The classifier also includes "damper" terms (like "unsubscribe" and "privacy policy") that lower the score when they appear, since legitimate emails commonly include them.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 20 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Zap className="w-5 h-5 text-primary" />
              2. TF-IDF + Linear SVM Classifier
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              A Support Vector Machine (SVM) is a machine learning model that draws a decision boundary between phishing and legitimate emails in high-dimensional feature space. We combine TF-IDF vectorization with a pre-trained Linear SVM for classification.
            </p>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-mono text-muted-foreground mb-2">How it works:</p>
              <p className="text-xs font-mono">decision = w . x + b</p>
              <ul className="text-xs text-muted-foreground mt-2 space-y-1">
                <li><span className="font-medium text-foreground">x</span> — TF-IDF feature vector (150 dimensions for vocabulary terms)</li>
                <li><span className="font-medium text-foreground">w</span> — pre-trained weight vector (learned from phishing corpus)</li>
                <li><span className="font-medium text-foreground">b</span> — bias term (decision threshold)</li>
                <li><span className="font-medium text-foreground">sigmoid(decision)</span> — converts to probability (0-100%)</li>
              </ul>
            </div>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-medium mb-1">Bigram Feature Extraction</p>
              <p className="text-xs text-muted-foreground">
                Beyond single words, the SVM also detects two-word combinations (bigrams) that are strongly associated with phishing. This captures phrases like "account suspended," "verify identity," and "wire transfer" that are more suspicious as pairs than individually.
              </p>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {["account suspended", "verify identity", "wire transfer", "enable macros", "act immediately", "arrest warrant"].map((term) => (
                  <span key={term} className="px-2 py-0.5 rounded bg-red-500/10 text-red-500 text-xs font-mono">{term}</span>
                ))}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              The SVM outputs a phishing probability (0-100%) along with the top contributing features, showing which words most influenced the classification decision.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 15 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Brain className="w-5 h-5 text-primary" />
              3. DistilBERT Deep Learning Classifier
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              GHOULPhishGuard uses a real DistilBERT model fine-tuned specifically for phishing email detection. DistilBERT is a compressed version of BERT that retains 97% of the language understanding capability while being 60% faster and 40% smaller.
            </p>
            <div className="bg-emerald-500/10 rounded-md p-3">
              <p className="text-xs font-medium text-emerald-700 mb-1">Real Model</p>
              <p className="text-xs text-muted-foreground">
                Model: <span className="font-mono font-medium text-foreground">cybersectony/phishing-email-detection-distilbert_v2.4.1</span>
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                This model was trained on a large dataset of phishing and legitimate emails and runs locally using ONNX Runtime (quantized INT8 for efficiency). No data is sent to external servers.
              </p>
            </div>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-mono text-muted-foreground mb-2">Architecture:</p>
              <ul className="text-xs text-muted-foreground space-y-1">
                <li><span className="font-medium text-foreground">WordPiece Tokenization</span> — splits text into subword tokens using a 30K vocabulary</li>
                <li><span className="font-medium text-foreground">6 Transformer Layers</span> — each with multi-head self-attention and feed-forward networks</li>
                <li><span className="font-medium text-foreground">Self-Attention</span> — each token "attends" to every other token to capture context</li>
                <li><span className="font-medium text-foreground">Classification Head</span> — final layer outputs phishing vs legitimate probability</li>
              </ul>
            </div>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-medium mb-1">Self-Attention Mechanism</p>
              <p className="text-xs text-muted-foreground">
                The key innovation of BERT is self-attention. For each word, it computes how much "attention" to pay to every other word in the email. This means it can understand that "click" near "verify" and "suspended" is suspicious, even if those words are far apart in the text.
              </p>
              <p className="text-xs font-mono text-muted-foreground mt-2">
                attention(Q, K, V) = softmax(QK&#x1D40; / &#x221A;d) . V
              </p>
            </div>
            <p className="text-xs text-muted-foreground">
              If the real model is loading or unavailable, GHOULPhishGuard falls back to a simulated BERT classifier with pre-trained weights for uninterrupted analysis.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 30 points (real model) / 15 points (simulated fallback)</p>
          </CardContent>
        </Card>

        <Card className="bg-muted/50">
          <CardContent className="pt-4">
            <div className="flex items-start gap-3">
              <Layers className="w-5 h-5 text-primary mt-0.5 shrink-0" />
              <div>
                <p className="text-sm font-medium mb-2">Ensemble Scoring</p>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  All three ML classifiers (TF-IDF, SVM, BERT) contribute to the final score independently. Using multiple models together is called an "ensemble" approach — it is more robust than any single model because different classifiers catch different types of phishing. If all three agree the email is phishing, the combined ML contribution can reach up to 50 points. The remaining points come from rule-based checks (headers, links, domains, attachments).
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
              Attackers often create domain names that look similar to real companies. We use three methods to catch these:
            </p>
            <div className="space-y-3">
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Levenshtein Distance (Typosquatting)</p>
                <p className="text-xs text-muted-foreground">
                  Measures how many character changes are needed to turn one domain into another. If a domain is only 1-2 changes away from a known brand, it is flagged as a typosquatting attempt.
                </p>
                <div className="mt-2 space-y-1 text-xs font-mono">
                  <p><span className="text-red-500">paypa1.com</span> → paypal.com <span className="text-muted-foreground">(1 change: "1" → "l")</span></p>
                  <p><span className="text-red-500">arnazon.com</span> → amazon.com <span className="text-muted-foreground">(1 change: "rn" → "m")</span></p>
                  <p><span className="text-red-500">goggle.com</span> → google.com <span className="text-muted-foreground">(1 change: "o" → "g")</span></p>
                </div>
              </div>

              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Homoglyph Detection (Look-alike Characters)</p>
                <p className="text-xs text-muted-foreground">
                  Detects when attackers use characters that look visually similar to fool human readers.
                </p>
                <div className="mt-2 space-y-1 text-xs font-mono">
                  <p><span className="text-red-500">rn</span> looks like <span className="text-emerald-500">m</span></p>
                  <p><span className="text-red-500">0</span> (zero) looks like <span className="text-emerald-500">o</span> (letter)</p>
                  <p><span className="text-red-500">1</span> (one) looks like <span className="text-emerald-500">l</span> (letter L)</p>
                  <p><span className="text-red-500">vv</span> looks like <span className="text-emerald-500">w</span></p>
                </div>
              </div>

              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Brand Name in Domain</p>
                <p className="text-xs text-muted-foreground">
                  Catches when a brand name is embedded in a completely different domain to create a false sense of legitimacy.
                </p>
                <div className="mt-2 text-xs font-mono">
                  <p><span className="text-red-500">microsoft-security-alert.com</span> <span className="text-muted-foreground">— not microsoft.com</span></p>
                  <p><span className="text-red-500">paypal-login-verify.com</span> <span className="text-muted-foreground">— not paypal.com</span></p>
                </div>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              We track 30+ major brands (Microsoft, Google, PayPal, Amazon, banks, shipping companies) and their legitimate alternative domains to avoid false positives.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: 20-30 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-primary" />
              5. Email Authentication (SPF / DKIM / DMARC)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Email has built-in security systems that verify whether the sender is who they claim to be. We parse the email headers to check all three:
            </p>
            <div className="space-y-3">
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">SPF (Sender Policy Framework)</p>
                <p className="text-xs text-muted-foreground">
                  Checks if the sending server is authorized to send email for the claimed domain. If the domain says "I only send from servers A and B" but the email came from server C, SPF fails.
                </p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">DKIM (DomainKeys Identified Mail)</p>
                <p className="text-xs text-muted-foreground">
                  Verifies that the email content has not been altered in transit. The sending server signs the email with a cryptographic key, and the receiving server checks that signature.
                </p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">DMARC (Domain-based Message Authentication)</p>
                <p className="text-xs text-muted-foreground">
                  Combines SPF and DKIM results with the domain owner's policy. It tells the receiving server what to do if authentication fails — reject the email, quarantine it, or let it through.
                </p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              When all three pass, you can be more confident the email is legitimate. When they fail, it is a strong indicator of spoofing. This analysis requires the raw email headers from "Show Original."
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 55 points (combined failures)</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <LinkIcon className="w-5 h-5 text-primary" />
              6. Link Deception Analysis
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              We compare the visible link text with the actual destination URL. Phishing emails often display a legitimate-looking URL while hiding the real malicious destination.
            </p>
            <div className="bg-muted rounded-md p-3 text-xs font-mono space-y-1">
              <p className="text-muted-foreground">Displayed: <span className="text-emerald-500">https://paypal.com/verify</span></p>
              <p className="text-muted-foreground">Actual: <span className="text-red-500">https://paypal-login-safe-check.com/verify</span></p>
            </div>
            <p className="text-xs text-muted-foreground">
              We also detect when links contain brand names in the URL to impersonate them (e.g., a link with "microsoft" in the hostname that does not actually go to microsoft.com).
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: 15-40 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <FileText className="w-5 h-5 text-primary" />
              7. Content Pattern Analysis
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Beyond TF-IDF, we use rule-based pattern matching to detect specific categories of phishing language:
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Urgency Patterns (+10)</p>
                <p className="text-xs text-muted-foreground">"immediately," "within 24 hours," "account will be closed," "final warning"</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Emotional Pressure (+8)</p>
                <p className="text-xs text-muted-foreground">"account compromised," "security alert," "won a prize," "unusual login"</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Sensitive Info Requests (+12)</p>
                <p className="text-xs text-muted-foreground">"password," "bank account," "credit card," "routing number," "payroll details"</p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Platform Abuse (+8)</p>
                <p className="text-xs text-muted-foreground">Links to Google Forms, Google Sites, SharePoint, or other legitimate platforms used for phishing</p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 38 points (combined)</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Mail className="w-5 h-5 text-primary" />
              8. Domain Mismatch Detection
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              We compare the "From" address with the "Reply-To" and "Return-Path" addresses. In phishing emails, these often point to different domains because the attacker wants replies to go to their own address.
            </p>
            <div className="bg-muted rounded-md p-3 text-xs font-mono space-y-1">
              <p className="text-muted-foreground">From: <span className="text-foreground">security@paypal.com</span></p>
              <p className="text-muted-foreground">Reply-To: <span className="text-red-500">support@paypal-verify-account.com</span></p>
            </div>
            <p className="text-xs text-muted-foreground">
              Note: Some legitimate emails have different Return-Path addresses (e.g., emails sent through SendGrid or Mailchimp). GHOULPhishGuard accounts for this and does not over-flag these cases.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 32 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Paperclip className="w-5 h-5 text-primary" />
              9. Attachment Risk Assessment
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Certain file types are commonly used in phishing attacks because they can execute code or contain macros. We flag emails containing these risky file types:
            </p>
            <div className="flex flex-wrap gap-1.5 mt-1">
              {[".zip", ".exe", ".js", ".iso", ".html", ".docm", ".xlsm", ".scr"].map((ext) => (
                <span key={ext} className="px-2 py-0.5 rounded bg-red-500/10 text-red-500 text-xs font-mono">{ext}</span>
              ))}
            </div>
            <p className="text-xs text-muted-foreground font-medium">Contribution: 12 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Clock className="w-5 h-5 text-primary" />
              10. Time-of-Day Anomaly Detection
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Phishing campaigns are often automated and can fire at unusual hours. We analyze the email's Date header to flag emails sent during suspicious times, particularly late-night weekend hours, which are common for automated phishing.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: 8-10 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Search className="w-5 h-5 text-primary" />
              11. URL Reputation & Domain Age
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Newly registered domains are a strong phishing indicator. Attackers frequently register domains just hours before a campaign and discard them afterwards. GHOULPhishGuard queries RDAP (Registration Data Access Protocol) to determine when a domain was created.
            </p>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-mono text-muted-foreground mb-2">Domain age scoring:</p>
              <ul className="text-xs text-muted-foreground space-y-1">
                <li><span className="font-medium text-red-500">&lt; 7 days</span> — extremely suspicious (+15 points)</li>
                <li><span className="font-medium text-orange-500">&lt; 30 days</span> — very recently created (+10 points)</li>
                <li><span className="font-medium text-amber-500">&lt; 90 days</span> — relatively new (+5 points)</li>
              </ul>
            </div>
            <div className="bg-muted rounded-md p-3">
              <p className="text-xs font-medium mb-1">Additional Checks</p>
              <ul className="text-xs text-muted-foreground space-y-1">
                <li><span className="font-medium text-foreground">Suspicious TLDs</span> — flags 37+ high-risk TLDs (.tk, .ml, .xyz, .top, etc.) commonly abused by phishing campaigns (+8 points)</li>
                <li><span className="font-medium text-foreground">Free Hosting Detection</span> — identifies domains on free hosting platforms (Heroku, Netlify, ngrok, etc.) that are commonly used for throwaway phishing sites (+6 points)</li>
              </ul>
            </div>
            <p className="text-xs text-muted-foreground">
              RDAP lookups use a 3-second timeout. If the lookup fails or is unavailable, the analysis continues without domain age data — no external dependency is required.
            </p>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 20 points</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <Database className="w-5 h-5 text-primary" />
              12. Threat Intelligence Enrichment
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground leading-relaxed">
              GHOULPhishGuard cross-references domains and URLs against multiple threat intelligence sources to identify known phishing infrastructure.
            </p>
            <div className="space-y-3">
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Domain Entropy Scoring</p>
                <p className="text-xs text-muted-foreground">
                  Calculates Shannon entropy to detect randomly generated domain names. Phishing domains often use random character strings (e.g., "xk4j9f2m.xyz") that have high entropy scores. Domains with entropy above 3.5 and length above 10 characters are flagged as suspicious.
                </p>
                <p className="text-xs font-mono text-muted-foreground mt-2">
                  H = -&#x2211; p(x) log&#x2082; p(x)
                </p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Phishing Pattern Database</p>
                <p className="text-xs text-muted-foreground">
                  Matches domains against 20+ known phishing naming patterns including "secure-login," "account-verify," "reset-password," and brand+action combinations (e.g., "paypal-login," "microsoft-verify").
                </p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">URL Shortener Detection</p>
                <p className="text-xs text-muted-foreground">
                  Identifies 20+ URL shortener services (bit.ly, tinyurl.com, t.co, etc.) that are often used to mask the real destination of phishing links.
                </p>
              </div>
              <div className="bg-muted rounded-md p-3">
                <p className="text-xs font-medium mb-1">Advanced Indicators</p>
                <ul className="text-xs text-muted-foreground space-y-1 mt-1">
                  <li><span className="font-medium text-foreground">Excessive subdomains</span> — more than 4 subdomain levels (e.g., secure.login.paypal.verify.evil.com)</li>
                  <li><span className="font-medium text-foreground">Raw IP addresses</span> — links pointing to IP addresses instead of domain names</li>
                  <li><span className="font-medium text-foreground">Homograph attacks</span> — non-ASCII characters that mimic standard Latin letters (IDN abuse)</li>
                  <li><span className="font-medium text-foreground">Google Safe Browsing</span> — queries the Transparency API for known dangerous sites</li>
                </ul>
              </div>
            </div>
            <p className="text-xs text-muted-foreground font-medium">Contribution: up to 25 points</p>
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
