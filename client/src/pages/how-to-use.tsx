import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import {
  BookOpen,
  Mail,
  FileText,
  MousePointerClick,
  Eye,
  Copy,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Monitor,
  Smartphone,
} from "lucide-react";

export default function HowToUse() {
  return (
    <div className="max-w-3xl mx-auto p-4 sm:p-6 space-y-8">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-3" data-testid="heading-how-to-use">
          <BookOpen className="w-6 h-6 text-primary" />
          How to Use PhishGuard
        </h1>
        <p className="text-muted-foreground">
          This guide shows you how to collect the information you need from a suspicious email and paste it into our analyzer.
        </p>
      </div>

      <div className="space-y-2">
        <h2 className="text-lg font-semibold">What You Need</h2>
        <p className="text-sm text-muted-foreground">
          To analyze an email, you can provide as much or as little as you have. The more information you give, the more accurate the analysis.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-500 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Basic (minimum)</p>
                  <p className="text-xs text-muted-foreground mt-1">Sender email address, subject line, and the email body text. This enables content analysis and TF-IDF scoring.</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-primary mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Full analysis (recommended)</p>
                  <p className="text-xs text-muted-foreground mt-1">Everything above plus the raw email headers. This unlocks SPF, DKIM, and DMARC verification.</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Monitor className="w-5 h-5 text-muted-foreground" />
          Getting Email Headers from Gmail (Desktop)
        </h2>

        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary text-primary-foreground text-xs font-bold">1</span>
                Open the suspicious email
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                In Gmail, click on the email you want to analyze. Make sure the full email is open, not just the preview.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary text-primary-foreground text-xs font-bold">2</span>
                Click the three-dot menu
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                In the top-right corner of the email, click the three vertical dots (more options menu). Look for <span className="font-medium text-foreground">"Show original"</span> and click it. This opens a new tab with the full email source.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary text-primary-foreground text-xs font-bold">3</span>
                Copy the headers
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                In the "Original Message" view, you will see the raw email source. The <span className="font-medium text-foreground">headers are everything above the email body</span> — they start with lines like <code className="text-xs bg-muted px-1 py-0.5 rounded">Delivered-To:</code>, <code className="text-xs bg-muted px-1 py-0.5 rounded">Received:</code>, and <code className="text-xs bg-muted px-1 py-0.5 rounded">Authentication-Results:</code>.
              </p>
              <p className="text-sm text-muted-foreground">
                Select and copy all the header text. You can also click the <span className="font-medium text-foreground">"Copy to clipboard"</span> button at the top if Gmail provides one.
              </p>
              <div className="bg-muted rounded-md p-3 text-xs font-mono space-y-0.5 overflow-x-auto">
                <p className="text-muted-foreground">Delivered-To: you@gmail.com</p>
                <p className="text-muted-foreground">Received: from mail-server.example.com ...</p>
                <p className="text-primary font-medium">Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass</p>
                <p className="text-primary font-medium">Received-SPF: pass (google.com: ...)</p>
                <p className="text-muted-foreground">From: sender@example.com</p>
                <p className="text-muted-foreground">Reply-To: reply@example.com</p>
                <p className="text-muted-foreground">Subject: Important notification</p>
                <p className="text-muted-foreground">Date: Mon, 6 Mar 2026 10:30:00 -0800</p>
              </div>
              <p className="text-xs text-muted-foreground">
                The highlighted lines above are the authentication headers that PhishGuard uses to check SPF, DKIM, and DMARC.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary text-primary-foreground text-xs font-bold">4</span>
                Paste into PhishGuard
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Go to the <Link href="/"><span className="text-primary underline cursor-pointer">Analyze page</span></Link> and fill in:
              </p>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li className="flex items-start gap-2">
                  <Mail className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
                  <span><span className="font-medium text-foreground">Sender Email</span> — the "From" address of the suspicious email</span>
                </li>
                <li className="flex items-start gap-2">
                  <FileText className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
                  <span><span className="font-medium text-foreground">Subject</span> — the full subject line</span>
                </li>
                <li className="flex items-start gap-2">
                  <Eye className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
                  <span><span className="font-medium text-foreground">Email Body</span> — copy and paste the full text of the email</span>
                </li>
                <li className="flex items-start gap-2">
                  <Copy className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
                  <span><span className="font-medium text-foreground">Raw Headers</span> — paste the headers you copied from "Show original"</span>
                </li>
              </ul>
              <p className="text-sm text-muted-foreground">
                Then click <span className="font-medium text-foreground">Analyze Email</span> and PhishGuard will give you a risk score, explain what it found, and recommend what to do.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Smartphone className="w-5 h-5 text-muted-foreground" />
          Getting Headers from Other Email Providers
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Card>
            <CardContent className="pt-4 space-y-2">
              <p className="text-sm font-medium">Outlook / Microsoft 365</p>
              <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
                <li>Open the email</li>
                <li>Click the three dots at the top right</li>
                <li>Select <span className="font-medium text-foreground">View &gt; View message source</span></li>
                <li>Copy everything and paste into PhishGuard</li>
              </ol>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4 space-y-2">
              <p className="text-sm font-medium">Yahoo Mail</p>
              <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
                <li>Open the email</li>
                <li>Click the three dots (more actions)</li>
                <li>Select <span className="font-medium text-foreground">View raw message</span></li>
                <li>Copy everything and paste into PhishGuard</li>
              </ol>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4 space-y-2">
              <p className="text-sm font-medium">Apple Mail</p>
              <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
                <li>Open the email</li>
                <li>Go to <span className="font-medium text-foreground">View &gt; Message &gt; All Headers</span></li>
                <li>Or use <span className="font-medium text-foreground">View &gt; Message &gt; Raw Source</span></li>
                <li>Copy and paste into PhishGuard</li>
              </ol>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4 space-y-2">
              <p className="text-sm font-medium">Thunderbird</p>
              <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
                <li>Open the email</li>
                <li>Go to <span className="font-medium text-foreground">View &gt; Message Source</span></li>
                <li>Or press <code className="bg-muted px-1 py-0.5 rounded">Ctrl+U</code></li>
                <li>Copy and paste into PhishGuard</li>
              </ol>
            </CardContent>
          </Card>
        </div>
      </div>

      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="pt-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-primary mt-0.5 shrink-0" />
            <div className="space-y-2">
              <p className="text-sm font-medium">Important: Do not click links in suspicious emails</p>
              <p className="text-xs text-muted-foreground">
                When examining a suspicious email, never click on any links inside it. Instead, hover over links to see where they actually point, and copy/paste the URL text manually into the Links section of the analyzer if needed. If you accidentally click a link, close the page immediately and change your passwords.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-center">
        <Link href="/">
          <Button data-testid="button-go-analyze">
            <ArrowRight className="w-4 h-4 mr-2" />
            Go to Email Analyzer
          </Button>
        </Link>
      </div>
    </div>
  );
}
