import { useEffect, useRef, type ReactNode } from "react";
import { ClerkProvider, SignIn, SignUp, useClerk } from "@clerk/react";
import { publishableKeyFromHost } from "@clerk/react/internal";
import { dark } from "@clerk/themes";
import { QueryClient, QueryClientProvider, useQueryClient } from "@tanstack/react-query";
import { Route, Switch, useLocation, Router as WouterRouter } from "wouter";
import { ErrorBoundary } from "@/components/error-boundary";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AppShell } from "@/components/app/shell";
import { usePageMeta } from "@/lib/session";
import NotFound from "@/pages/not-found";
import Landing from "@/pages/landing";
import Onboarding from "@/pages/onboarding";
import Dashboard from "@/pages/dashboard";
import Devices from "@/pages/devices";
import DeviceDetailPage from "@/pages/device-detail";
import Enroll from "@/pages/enroll";
import Findings from "@/pages/findings";
import Vulnerabilities from "@/pages/vulnerabilities";
import Reports from "@/pages/reports";
import EmailSecurity from "@/pages/email-security";
import SettingsPage from "@/pages/settings";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 15_000 } },
});

// REQUIRED — copy verbatim.
const clerkPubKey = publishableKeyFromHost(
  window.location.hostname,
  import.meta.env.VITE_CLERK_PUBLISHABLE_KEY,
);

// REQUIRED — copy verbatim. Empty in dev, auto-set in prod.
const clerkProxyUrl = import.meta.env.VITE_CLERK_PROXY_URL;

const basePath = import.meta.env.BASE_URL.replace(/\/$/, "");

function stripBase(path: string): string {
  return basePath && path.startsWith(basePath)
    ? path.slice(basePath.length) || "/"
    : path;
}

if (!clerkPubKey) {
  throw new Error("Missing VITE_CLERK_PUBLISHABLE_KEY in .env file");
}

const clerkAppearance = {
  theme: dark,
  cssLayerName: "clerk",
  options: {
    logoPlacement: "inside" as const,
    logoLinkUrl: basePath || "/",
    logoImageUrl: `${window.location.origin}${basePath}/logo.svg`,
  },
  variables: {
    colorPrimary: "#7568E8",
    colorForeground: "#F8FAFC",
    colorMutedForeground: "#A3ACC2",
    colorDanger: "#EF4444",
    colorBackground: "#161B30",
    colorInput: "#0F1325",
    colorInputForeground: "#F8FAFC",
    colorNeutral: "#F8FAFC",
    fontFamily: "'Geist', ui-sans-serif, system-ui, sans-serif",
    borderRadius: "0.65rem",
  },
  elements: {
    rootBox: "w-full flex justify-center",
    cardBox: "bg-[#161B30] border border-[#2A3150] rounded-2xl w-[440px] max-w-full overflow-hidden shadow-[0_30px_80px_-30px_rgba(4,6,20,0.9)]",
    card: "!shadow-none !border-0 !bg-transparent !rounded-none",
    footer: "!shadow-none !border-0 !bg-transparent !rounded-none",
    headerTitle: "text-[#F8FAFC] text-xl font-semibold tracking-tight",
    headerSubtitle: "text-[#A3ACC2]",
    socialButtonsBlockButtonText: "text-[#F8FAFC] font-medium",
    formFieldLabel: "text-[#D5DAE6] text-[13px] font-medium",
    footerActionLink: "text-[#38BDF8] font-medium",
    footerActionText: "text-[#A3ACC2]",
    dividerText: "text-[#8A93AB] text-xs",
    identityPreviewEditButton: "text-[#38BDF8]",
    formFieldSuccessText: "text-[#22C55E]",
    alertText: "text-[#F8FAFC]",
    logoBox: "flex justify-center h-11",
    logoImage: "h-11 w-11",
    socialButtonsBlockButton: "bg-[#1B2140] border border-[#2A3150] text-[#F8FAFC]",
    formButtonPrimary: "bg-[#7568E8] text-[#F8FAFC] font-medium shadow-none normal-case",
    formFieldInput: "bg-[#0F1325] border border-[#2A3150] text-[#F8FAFC]",
    footerAction: "bg-[#131728] border-t border-[#232A47] py-4",
    dividerLine: "bg-[#2A3150]",
    alert: "bg-[#2a1416] border border-[#EF4444]/40",
    otpCodeFieldInput: "bg-[#0F1325] border border-[#2A3150] text-[#F8FAFC]",
    formFieldRow: "gap-3",
    main: "gap-5",
  },
};

function AuthFrame({ children }: { children: ReactNode }) {
  return (
    <div className="relative flex min-h-[100dvh] flex-col items-center justify-center bg-background px-4 py-12">
      <div className="grid-bg pointer-events-none absolute inset-0 [mask-image:radial-gradient(ellipse_at_center,black_20%,transparent_70%)]" />
      <div className="relative">{children}</div>
      <p className="relative mt-6 max-w-sm text-center text-xs text-muted-foreground">
        Creating an account gives you an identity only. To join an existing organization, an owner must authorize your email address.
      </p>
    </div>
  );
}

function SignInPage() {
  usePageMeta("Sign in", "Sign in to NextAura Security Center.");
  return (
    <AuthFrame>
      <SignIn routing="path" path={`${basePath}/sign-in`} signUpUrl={`${basePath}/sign-up`} />
    </AuthFrame>
  );
}

function SignUpPage() {
  usePageMeta("Create account", "Create a NextAura Security Center identity.");
  return (
    <AuthFrame>
      <SignUp routing="path" path={`${basePath}/sign-up`} signInUrl={`${basePath}/sign-in`} />
    </AuthFrame>
  );
}

function ClerkQueryClientCacheInvalidator() {
  const { addListener } = useClerk();
  const queryClient = useQueryClient();
  const prevUserIdRef = useRef<string | null | undefined>(undefined);

  useEffect(() => {
    const unsubscribe = addListener(({ user }) => {
      const userId = user?.id ?? null;
      if (prevUserIdRef.current !== undefined && prevUserIdRef.current !== userId) {
        queryClient.clear();
      }
      prevUserIdRef.current = userId;
    });
    return unsubscribe;
  }, [addListener, queryClient]);

  return null;
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function Router() {
  return (
    <AppShell>
      <RoutedErrorBoundary>
        <Switch>
          <Route path="/" component={Landing} />
          <Route path="/sign-in/*?" component={SignInPage} />
          <Route path="/sign-up/*?" component={SignUpPage} />
          <Route path="/onboarding" component={Onboarding} />
          <Route path="/dashboard" component={Dashboard} />
          <Route path="/devices" component={Devices} />
          <Route path="/devices/enroll" component={Enroll} />
          <Route path="/devices/:id" component={DeviceDetailPage} />
          <Route path="/findings" component={Findings} />
          <Route path="/vulnerabilities" component={Vulnerabilities} />
          <Route path="/reports" component={Reports} />
          <Route path="/email-security" component={EmailSecurity} />
          <Route path="/settings" component={SettingsPage} />
          <Route component={NotFound} />
        </Switch>
      </RoutedErrorBoundary>
    </AppShell>
  );
}

function ClerkProviderWithRoutes() {
  const [, setLocation] = useLocation();

  return (
    <ClerkProvider
      publishableKey={clerkPubKey}
      proxyUrl={clerkProxyUrl}
      appearance={clerkAppearance}
      signInUrl={`${basePath}/sign-in`}
      signUpUrl={`${basePath}/sign-up`}
      localization={{
        signIn: {
          start: {
            title: "Sign in to Security Center",
            subtitle: "Visibility. Detection. Confidence.",
          },
        },
        signUp: {
          start: {
            title: "Create your identity",
            subtitle: "An owner must authorize you before you can join their organization.",
          },
        },
      }}
      routerPush={(to) => setLocation(stripBase(to))}
      routerReplace={(to) => setLocation(stripBase(to), { replace: true })}
    >
      <QueryClientProvider client={queryClient}>
        <ClerkQueryClientCacheInvalidator />
        <TooltipProvider>
          <Router />
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ClerkProvider>
  );
}

function App() {
  return (
    <WouterRouter base={basePath}>
      <ClerkProviderWithRoutes />
    </WouterRouter>
  );
}

export default App;
