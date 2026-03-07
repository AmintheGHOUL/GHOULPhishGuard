import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import {
  AlertTriangle,
  Shield,
  Mail,
  LinkIcon,
  Eye,
  Lock,
  Clock,
  Gift,
  CreditCard,
  UserX,
  ArrowRight,
  CheckCircle2,
  XCircle,
} from "lucide-react";

export default function Awareness() {
  return (
    <div className="max-w-3xl mx-auto p-4 sm:p-6 space-y-8">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-3" data-testid="heading-awareness">
          <AlertTriangle className="w-6 h-6 text-primary" />
          Phishing Awareness Guide
        </h1>
        <p className="text-muted-foreground">
          Phishing is one of the most common cyber attacks. This guide will help you recognize phishing emails and protect yourself.
        </p>
      </div>

      <div className="space-y-3">
        <h2 className="text-lg font-semibold">What is Phishing?</h2>
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-muted-foreground leading-relaxed">
              Phishing is when someone sends you a fake email pretending to be a company, bank, or person you trust. Their goal is to trick you into giving away personal information like passwords, credit card numbers, or bank details. The email might look real, use the same logo and colors as the real company, and even come from an address that looks similar to the real one.
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-4">
        <h2 className="text-lg font-semibold">Common Warning Signs</h2>
        <p className="text-sm text-muted-foreground">If you see any of these in an email, be cautious:</p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <Clock className="w-5 h-5 text-orange-500 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Urgency and Pressure</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    "Your account will be closed in 24 hours!" or "Verify immediately or lose access." Real companies rarely give you a deadline of hours to take action.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <LinkIcon className="w-5 h-5 text-red-500 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Suspicious Links</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    A link might say "paypal.com" but actually go to "paypal-login-check.ru". Always hover over a link to see the real address before clicking.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <CreditCard className="w-5 h-5 text-red-500 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Asking for Sensitive Information</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Requests for passwords, credit card numbers, bank details, or Social Security numbers. Legitimate companies will never ask for this by email.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <UserX className="w-5 h-5 text-orange-500 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Generic Greetings</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    "Dear Customer" or "Dear User" instead of your real name. Companies that know you will usually use your name.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <Mail className="w-5 h-5 text-orange-500 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Fake Sender Addresses</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    The email might come from "support@microsoft-security-alert.com" instead of "support@microsoft.com". Attackers use similar-looking domains.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <Gift className="w-5 h-5 text-orange-500 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Too-Good-To-Be-True Offers</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    "You won a $1,000 gift card!" or "Congratulations, you've been selected!" If it sounds too good to be true, it probably is.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="space-y-4">
        <h2 className="text-lg font-semibold">Real Examples</h2>

        <Card className="border-red-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2 text-red-500">
              <XCircle className="w-4 h-4" />
              Phishing Email Example
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="bg-muted rounded-md p-4 text-sm space-y-2">
              <p><span className="text-muted-foreground">From:</span> <span className="font-mono text-xs">security@paypa1-verify.com</span></p>
              <p><span className="text-muted-foreground">Subject:</span> <span className="font-medium">URGENT: Your account has been suspended</span></p>
              <p className="text-muted-foreground text-xs mt-2 leading-relaxed">
                Dear Customer, we have detected unauthorized activity on your PayPal account. Your account has been temporarily suspended. You must verify your identity within 24 hours or your account will be permanently closed. Click here to restore your account: <span className="text-red-500 underline">https://paypal-login-verify.com/restore</span>
              </p>
            </div>
            <div className="mt-3 space-y-1">
              <p className="text-xs text-red-500 flex items-center gap-1"><XCircle className="w-3 h-3" /> Fake domain: "paypa1-verify.com" (uses number 1 instead of letter l)</p>
              <p className="text-xs text-red-500 flex items-center gap-1"><XCircle className="w-3 h-3" /> Creates urgency with "24 hours" deadline</p>
              <p className="text-xs text-red-500 flex items-center gap-1"><XCircle className="w-3 h-3" /> Generic greeting "Dear Customer"</p>
              <p className="text-xs text-red-500 flex items-center gap-1"><XCircle className="w-3 h-3" /> Fake link that mimics PayPal</p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-emerald-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2 text-emerald-500">
              <CheckCircle2 className="w-4 h-4" />
              Legitimate Email Example
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="bg-muted rounded-md p-4 text-sm space-y-2">
              <p><span className="text-muted-foreground">From:</span> <span className="font-mono text-xs">no-reply@accounts.google.com</span></p>
              <p><span className="text-muted-foreground">Subject:</span> <span className="font-medium">Security alert - New sign-in to your Google Account</span></p>
              <p className="text-muted-foreground text-xs mt-2 leading-relaxed">
                A new sign-in was detected on your Google Account. If this was you, you can ignore this message. If not, review your recent activity. You received this email to let you know about important changes to your account.
              </p>
            </div>
            <div className="mt-3 space-y-1">
              <p className="text-xs text-emerald-500 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Real Google domain (accounts.google.com)</p>
              <p className="text-xs text-emerald-500 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> No urgency pressure — says "if this was you, ignore"</p>
              <p className="text-xs text-emerald-500 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> No request for sensitive information</p>
              <p className="text-xs text-emerald-500 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Links go to real Google domains</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" />
          How to Protect Yourself
        </h2>
        <div className="space-y-3">
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <Eye className="w-5 h-5 text-primary mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Always check the sender address</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Look at the actual email address, not just the display name. An email might show "Microsoft Support" as the name but come from "support@microsoft-check.com" which is not Microsoft.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <LinkIcon className="w-5 h-5 text-primary mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Hover before you click</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Move your mouse over any link to see the real destination URL in the bottom-left corner of your browser. If it does not match what the link text says, do not click it.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <Lock className="w-5 h-5 text-primary mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Go directly to the website</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Instead of clicking a link in an email, open your browser and type the company's real website address yourself. For example, go to paypal.com directly instead of clicking a link that claims to be PayPal.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-start gap-3">
                <Shield className="w-5 h-5 text-primary mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium">Use GHOULPhishGuard when in doubt</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    If you receive an email that feels off, paste its details into GHOULPhishGuard. Our analyzer will check for known phishing patterns, verify email authentication, and give you a plain-English explanation of what it found.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="flex justify-center gap-3">
        <Link href="/">
          <Button data-testid="button-go-analyze-from-awareness">
            <ArrowRight className="w-4 h-4 mr-2" />
            Analyze an Email
          </Button>
        </Link>
        <Link href="/techniques">
          <Button variant="outline" data-testid="button-go-techniques">
            How We Detect Phishing
          </Button>
        </Link>
      </div>
    </div>
  );
}
