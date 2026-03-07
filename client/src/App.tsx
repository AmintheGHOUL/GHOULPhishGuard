import { useEffect } from "react";
import { Switch, Route, Link, useLocation } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider, useTheme } from "@/components/theme-provider";
import { Button } from "@/components/ui/button";
import { Moon, Sun, Shield, Search, BookOpen, AlertTriangle, Cpu, Github, Newspaper } from "lucide-react";
import { cn } from "@/lib/utils";
import NotFound from "@/pages/not-found";
import Dashboard from "@/pages/dashboard";
import HowToUse from "@/pages/how-to-use";
import Awareness from "@/pages/awareness";
import Techniques from "@/pages/techniques";

function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  return (
    <Button size="icon" variant="ghost" onClick={toggleTheme} data-testid="button-theme-toggle">
      {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
    </Button>
  );
}

function NavLink({ href, children, icon: Icon }: { href: string; children: string; icon: typeof Search }) {
  const [location] = useLocation();
  const active = location === href;

  return (
    <Link href={href}>
      <span
        className={cn(
          "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors cursor-pointer",
          active
            ? "bg-primary/10 text-primary"
            : "text-muted-foreground hover:text-foreground hover:bg-muted"
        )}
        data-testid={`nav-${href.replace("/", "") || "home"}`}
      >
        <Icon className="w-3.5 h-3.5" />
        {children}
      </span>
    </Link>
  );
}

function AppRouter() {
  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/how-to-use" component={HowToUse} />
      <Route path="/awareness" component={Awareness} />
      <Route path="/techniques" component={Techniques} />
      <Route component={NotFound} />
    </Switch>
  );
}

function LinkedInBadge() {
  useEffect(() => {
    const existing = document.querySelector('script[src="https://platform.linkedin.com/badges/js/profile.js"]');
    if (existing) {
      existing.remove();
    }
    const script = document.createElement("script");
    script.src = "https://platform.linkedin.com/badges/js/profile.js";
    script.async = true;
    script.defer = true;
    script.type = "text/javascript";
    document.body.appendChild(script);
    return () => {
      script.remove();
    };
  }, []);

  return (
    <div
      className="badge-base LI-profile-badge"
      data-locale="en_US"
      data-size="medium"
      data-theme="dark"
      data-type="VERTICAL"
      data-vanity="amin-majdi-al-sammar"
      data-version="v1"
    >
      <a
        className="badge-base__link LI-simple-link"
        href="https://www.linkedin.com/in/amin-majdi-al-sammar?trk=profile-badge"
      >
        Amin Al-Sammar
      </a>
    </div>
  );
}

function AppLayout() {
  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b sticky top-0 z-50 bg-background">
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-2 px-4 py-2">
          <Link href="/">
            <span className="flex items-center gap-2.5 cursor-pointer">
              <div className="flex items-center justify-center w-8 h-8 rounded-md bg-primary">
                <Shield className="w-4 h-4 text-primary-foreground" />
              </div>
              <span className="font-semibold text-sm tracking-tight">GHOULPhishGuard</span>
            </span>
          </Link>
          <ThemeToggle />
        </div>
        <nav className="max-w-5xl mx-auto px-4 pb-2 flex items-center gap-1 overflow-x-auto" data-testid="main-nav">
          <NavLink href="/" icon={Search}>Analyze</NavLink>
          <NavLink href="/how-to-use" icon={BookOpen}>How to Use</NavLink>
          <NavLink href="/awareness" icon={AlertTriangle}>Phishing Awareness</NavLink>
          <NavLink href="/techniques" icon={Cpu}>Detection Techniques</NavLink>
        </nav>
      </header>
      <main className="flex-1">
        <AppRouter />
      </main>
      <footer className="border-t py-8 mt-8 bg-muted/30">
        <div className="max-w-5xl mx-auto px-4 space-y-4">
          <div className="text-center text-xs text-muted-foreground">
            GHOULPhishGuard — Email Threat Analyzer. Built for education and awareness.
          </div>
          
          <div className="flex flex-col sm:flex-row items-center justify-center gap-6 text-xs">
            <a
              href="https://github.com/AmintheGHOUL"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground transition-colors"
            >
              <Github className="w-3.5 h-3.5" />
              GitHub
            </a>
            <a
              href="https://amintheghoul.medium.com"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground transition-colors"
            >
              <Newspaper className="w-3.5 h-3.5" />
              Medium
            </a>
          </div>

          <div className="flex items-center justify-center pt-3">
            <LinkedInBadge />
          </div>
        </div>
      </footer>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <ThemeProvider>
          <AppLayout />
          <Toaster />
        </ThemeProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
