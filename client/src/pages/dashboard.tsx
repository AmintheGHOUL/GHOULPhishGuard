import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  Chrome,
  Download,
  Server,
  CheckCircle2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { AnalysisResult, EmailInput } from "@shared/schema";

function SetupInstructions() {
  const backendUrl = window.location.origin;

  return (
    <div className="space-y-4" data-testid="setup-instructions">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Download className="w-4 h-4 text-muted-foreground" />
              Step 1: Get Extension
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground space-y-2">
            <p>Download the extension files from this server:</p>
            <a
              href="/extension/manifest.json"
              target="_blank"
              className="block text-xs font-mono text-primary underline"
              data-testid="link-manifest"
            >
              /extension/manifest.json
            </a>
            <p className="text-xs">
              Save all files from <code className="text-xs bg-muted px-1 py-0.5 rounded">/extension/</code> into a local folder:
              manifest.json, content.js, content.css, popup.html
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Chrome className="w-4 h-4 text-muted-foreground" />
              Step 2: Load in Chrome
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground space-y-2">
            <ol className="space-y-1.5 text-xs list-decimal list-inside">
              <li>Go to <code className="bg-muted px-1 py-0.5 rounded">chrome://extensions</code></li>
              <li>Enable Developer mode (top right)</li>
              <li>Click "Load unpacked"</li>
              <li>Select the folder with the extension files</li>
            </ol>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Server className="w-4 h-4 text-muted-foreground" />
              Step 3: Configure Backend
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground space-y-2">
            <p className="text-xs">Click the PhishGuard icon in Chrome and set the backend URL to:</p>
            <code className="block text-xs bg-muted px-2 py-1.5 rounded font-mono break-all" data-testid="text-backend-url">
              {backendUrl}
            </code>
            <p className="text-xs">Then open Gmail and click on any email.</p>
          </CardContent>
        </Card>
      </div>

      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <CheckCircle2 className="w-3.5 h-3.5 text-primary" />
        <span>Backend is running and ready to receive requests from the extension.</span>
      </div>
    </div>
  );
}

function ManualAnalyzer() {
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
    <div className="space-y-4">
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
            className="flex items-center gap-2 text-xs text-muted-foreground hover-elevate px-3 py-2 rounded-md w-full"
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
    </div>
  );
}

export default function Dashboard() {
  return (
    <div className="max-w-3xl mx-auto p-4 sm:p-6 space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10">
          <Shield className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-semibold tracking-tight">PhishGuard</h1>
          <p className="text-sm text-muted-foreground">
            Email threat analysis with full header parsing
          </p>
        </div>
      </div>

      <Tabs defaultValue="analyze" className="w-full">
        <TabsList data-testid="tabs-nav">
          <TabsTrigger value="analyze" data-testid="tab-analyze">
            <Search className="w-3.5 h-3.5 mr-1.5" />
            Analyze
          </TabsTrigger>
          <TabsTrigger value="setup" data-testid="tab-setup">
            <Chrome className="w-3.5 h-3.5 mr-1.5" />
            Extension Setup
          </TabsTrigger>
        </TabsList>

        <TabsContent value="analyze" className="mt-4">
          <ManualAnalyzer />
        </TabsContent>

        <TabsContent value="setup" className="mt-4">
          <SetupInstructions />
        </TabsContent>
      </Tabs>
    </div>
  );
}
