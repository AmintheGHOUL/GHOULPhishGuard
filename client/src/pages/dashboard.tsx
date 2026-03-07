import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { AnalysisResultView } from "@/components/analysis-result";
import { Separator } from "@/components/ui/separator";
import {
  Shield,
  Search,
  Loader2,
  Plus,
  X,
  Mail,
  FileText,
  Link as LinkIcon,
  Paperclip,
  ChevronDown,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { AnalysisResult, EmailInput } from "@shared/schema";
import { Link } from "wouter";

export default function Dashboard() {
  const [fromEmail, setFromEmail] = useState("");
  const [subject, setSubject] = useState("");
  const [bodyText, setBodyText] = useState("");
  const [rawHeaders, setRawHeaders] = useState("");
  const [replyTo, setReplyTo] = useState("");
  const [returnPath, setReturnPath] = useState("");
  const [links, setLinks] = useState<Array<{ text: string; href: string }>>([]);
  const [attachments, setAttachments] = useState<Array<{ filename: string }>>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const analyzeMutation = useMutation({
    mutationFn: async (data: EmailInput) => {
      const res = await apiRequest("POST", "/api/analyze-email", data);
      return (await res.json()) as AnalysisResult;
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    analyzeMutation.mutate({
      fromEmail,
      subject,
      bodyText,
      rawHeaders,
      replyTo,
      returnPath,
      links,
      attachments,
      observedBrandDomains: [
        "microsoft.com", "paypal.com", "docusign.com", "amazon.com",
        "google.com", "apple.com", "netflix.com", "facebook.com",
      ],
    });
  };

  const addLink = () => setLinks([...links, { text: "", href: "" }]);
  const removeLink = (i: number) => setLinks(links.filter((_, idx) => idx !== i));
  const updateLink = (i: number, field: "text" | "href", value: string) => {
    const updated = [...links];
    updated[i] = { ...updated[i], [field]: value };
    setLinks(updated);
  };

  const addAttachment = () => setAttachments([...attachments, { filename: "" }]);
  const removeAttachment = (i: number) => setAttachments(attachments.filter((_, idx) => idx !== i));

  const handleReset = () => {
    setFromEmail("");
    setSubject("");
    setBodyText("");
    setRawHeaders("");
    setReplyTo("");
    setReturnPath("");
    setLinks([]);
    setAttachments([]);
    setShowAdvanced(false);
    analyzeMutation.reset();
  };

  return (
    <div className="max-w-3xl mx-auto p-4 sm:p-6 space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10">
          <Shield className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Email Analyzer</h1>
          <p className="text-sm text-muted-foreground">
            Paste email details below to check for phishing threats.{" "}
            <Link href="/how-to-use">
              <span className="text-primary underline cursor-pointer" data-testid="link-how-to-use">
                Learn how to get email data
              </span>
            </Link>
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Mail className="w-4 h-4 text-muted-foreground" />
              Email Details
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="fromEmail" className="text-xs">Sender Email</Label>
                <Input
                  id="fromEmail"
                  placeholder="sender@example.com"
                  value={fromEmail}
                  onChange={(e) => setFromEmail(e.target.value)}
                  data-testid="input-from-email"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="subject" className="text-xs">Subject Line</Label>
                <Input
                  id="subject"
                  placeholder="Urgent: Verify your account"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  data-testid="input-subject"
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="bodyText" className="text-xs">Email Body</Label>
              <Textarea
                id="bodyText"
                placeholder="Paste the full email body text here..."
                className="min-h-[100px] resize-y text-sm"
                value={bodyText}
                onChange={(e) => setBodyText(e.target.value)}
                data-testid="input-body-text"
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <FileText className="w-4 h-4 text-muted-foreground" />
              Raw Email Headers (for SPF/DKIM/DMARC analysis)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1.5">
              <Label htmlFor="rawHeaders" className="text-xs">
                Paste full headers from "Show Original" in Gmail
              </Label>
              <Textarea
                id="rawHeaders"
                placeholder={"Delivered-To: user@gmail.com\nReceived: from ...\nAuthentication-Results: mx.google.com; dkim=pass ...\nReceived-SPF: pass ..."}
                className="min-h-[100px] resize-y text-xs font-mono"
                value={rawHeaders}
                onChange={(e) => setRawHeaders(e.target.value)}
                data-testid="input-raw-headers"
              />
            </div>
          </CardContent>
        </Card>

        <div>
          <button
            type="button"
            className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground px-3 py-2 rounded-md w-full"
            onClick={() => setShowAdvanced(!showAdvanced)}
            data-testid="button-toggle-advanced"
          >
            <ChevronDown className={cn("w-3.5 h-3.5 transition-transform", showAdvanced && "rotate-180")} />
            Additional Options (links, attachments, reply-to)
          </button>
        </div>

        {showAdvanced && (
          <>
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Header Details</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label htmlFor="replyTo" className="text-xs">Reply-To</Label>
                    <Input
                      id="replyTo"
                      placeholder="reply@other-domain.com"
                      value={replyTo}
                      onChange={(e) => setReplyTo(e.target.value)}
                      data-testid="input-reply-to"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="returnPath" className="text-xs">Return-Path</Label>
                    <Input
                      id="returnPath"
                      placeholder="bounce@other-domain.com"
                      value={returnPath}
                      onChange={(e) => setReturnPath(e.target.value)}
                      data-testid="input-return-path"
                    />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between gap-1">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <LinkIcon className="w-4 h-4 text-muted-foreground" />
                    Links ({links.length})
                  </CardTitle>
                  <Button type="button" variant="ghost" size="sm" onClick={addLink} data-testid="button-add-link">
                    <Plus className="w-3.5 h-3.5 mr-1" /> Add
                  </Button>
                </div>
              </CardHeader>
              {links.length > 0 && (
                <CardContent className="space-y-2">
                  {links.map((link, i) => (
                    <div key={i} className="flex gap-2 items-start">
                      <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-2">
                        <Input placeholder="Visible text" value={link.text} onChange={(e) => updateLink(i, "text", e.target.value)} className="text-xs" data-testid={`input-link-text-${i}`} />
                        <Input placeholder="https://actual-url.com" value={link.href} onChange={(e) => updateLink(i, "href", e.target.value)} className="text-xs" data-testid={`input-link-href-${i}`} />
                      </div>
                      <Button type="button" variant="ghost" size="icon" onClick={() => removeLink(i)} data-testid={`button-remove-link-${i}`}>
                        <X className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  ))}
                </CardContent>
              )}
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between gap-1">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Paperclip className="w-4 h-4 text-muted-foreground" />
                    Attachments ({attachments.length})
                  </CardTitle>
                  <Button type="button" variant="ghost" size="sm" onClick={addAttachment} data-testid="button-add-attachment">
                    <Plus className="w-3.5 h-3.5 mr-1" /> Add
                  </Button>
                </div>
              </CardHeader>
              {attachments.length > 0 && (
                <CardContent className="space-y-2">
                  {attachments.map((att, i) => (
                    <div key={i} className="flex gap-2 items-center">
                      <Input
                        placeholder="invoice.zip"
                        value={att.filename}
                        onChange={(e) => {
                          const updated = [...attachments];
                          updated[i] = { filename: e.target.value };
                          setAttachments(updated);
                        }}
                        className="text-xs flex-1"
                        data-testid={`input-attachment-${i}`}
                      />
                      <Button type="button" variant="ghost" size="icon" onClick={() => removeAttachment(i)} data-testid={`button-remove-attachment-${i}`}>
                        <X className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  ))}
                </CardContent>
              )}
            </Card>
          </>
        )}

        <div className="flex gap-3 flex-wrap">
          <Button
            type="submit"
            disabled={analyzeMutation.isPending || (!fromEmail && !subject && !bodyText && !rawHeaders)}
            data-testid="button-analyze"
          >
            {analyzeMutation.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Search className="w-4 h-4 mr-2" />
            )}
            {analyzeMutation.isPending ? "Analyzing..." : "Analyze Email"}
          </Button>
          {(analyzeMutation.data || fromEmail || subject || bodyText || rawHeaders) && (
            <Button type="button" variant="secondary" onClick={handleReset} data-testid="button-reset">
              Clear
            </Button>
          )}
        </div>
      </form>

      {analyzeMutation.isError && (
        <Card className="border-destructive/30">
          <CardContent className="pt-4">
            <p className="text-sm text-destructive" data-testid="text-error">
              Analysis failed: {analyzeMutation.error.message}
            </p>
          </CardContent>
        </Card>
      )}

      {analyzeMutation.data && (
        <>
          <Separator />
          <AnalysisResultView result={analyzeMutation.data} />
        </>
      )}

      <Card className="border-muted bg-muted/30">
        <CardContent className="pt-4">
          <p className="text-xs text-muted-foreground text-center" data-testid="text-disclaimer">
            This tool provides automated analysis and cannot guarantee that an email is safe or malicious.
            Always exercise caution with suspicious emails. Your email content is analyzed in memory and never stored.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
