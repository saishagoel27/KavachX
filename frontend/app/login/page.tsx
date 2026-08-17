"use client";

import { ArrowRight, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { ApiError, endpoints, tokens } from "@/lib/api";
import { Chip, ErrorNote, Spinner } from "@/components/ui";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [orgName, setOrgName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; message: string; requestId: string } | null>(
    null,
  );
  const [config, setConfig] = useState<{ dev_mode: boolean; password_min_length: number } | null>(
    null,
  );

  useEffect(() => {
    void (async () => {
      try {
        const data = await fetch(
          `${process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"}/api/auth/config`,
        ).then((r) => r.json());
        setConfig(data);
      } catch {
        /* the form works without it; only the hint text depends on it */
      }
    })();
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const pair =
        mode === "login"
          ? await endpoints.login(email, password)
          : await endpoints.register({
              email,
              password,
              full_name: fullName,
              organisation_name: orgName,
            });
      tokens.set(pair.access_token, pair.refresh_token);
      router.replace("/console");
    } catch (exc) {
      if (exc instanceof ApiError) {
        setError({ code: exc.code, message: exc.message, requestId: exc.requestId });
      } else {
        setError({
          code: "NETWORK_ERROR",
          message:
            "Could not reach the KavachX API. Is the backend running on " +
            `${process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"}?`,
          requestId: "",
        });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="relative flex min-h-screen items-center justify-center px-6 py-12">
      <div className="grid-bg pointer-events-none absolute inset-0 opacity-60" aria-hidden />
      <div
        className="pointer-events-none absolute left-1/2 top-1/4 h-[420px] w-[720px] -translate-x-1/2
          bg-[radial-gradient(ellipse_at_center,rgba(0,242,255,0.1),transparent_65%)]"
        aria-hidden
      />

      <div className="relative w-full max-w-md">
        <Link href="/" className="mb-8 flex items-center justify-center gap-2.5">
          <ShieldCheck className="h-6 w-6 text-accent" />
          <span className="font-mono text-lg font-bold tracking-[0.22em]">KAVACHX</span>
        </Link>

        <div className="panel p-7">
          <div className="mb-6">
            <h1 className="text-headline-sm">
              {mode === "login" ? "Sign in to the console" : "Create your workspace"}
            </h1>
            <p className="mt-1.5 text-small text-foreground-muted">
              {mode === "login"
                ? "Graph-grounded autonomous cyber-reasoning with proof-carrying repair."
                : "You will be the OWNER of a new organisation with full policy control."}
            </p>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="label" htmlFor="email">
                Email
              </label>
              <input
                id="email"
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="field"
                placeholder="you@example.com"
              />
            </div>

            {mode === "register" && (
              <>
                <div>
                  <label className="label" htmlFor="full_name">
                    Full name
                  </label>
                  <input
                    id="full_name"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="field"
                    placeholder="optional"
                  />
                </div>
                <div>
                  <label className="label" htmlFor="org">
                    Organisation
                  </label>
                  <input
                    id="org"
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    className="field"
                    placeholder="Acme Security"
                  />
                </div>
              </>
            )}

            <div>
              <label className="label" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="field"
                placeholder="••••••••••••"
              />
              {mode === "register" && config && (
                <p className="mt-1.5 text-[11px] text-foreground-faint">
                  Minimum {config.password_min_length} characters.
                </p>
              )}
            </div>

            {error && (
              <ErrorNote
                title={mode === "login" ? "Sign-in failed" : "Registration failed"}
                detail={error.message}
                code={error.code}
                requestId={error.requestId}
              />
            )}

            <button type="submit" disabled={busy} className="btn-primary w-full">
              {busy ? <Spinner className="text-accent-on" /> : null}
              {mode === "login" ? "Sign in" : "Create workspace"}
              {!busy && <ArrowRight className="h-4 w-4" />}
            </button>
          </form>

          <div className="mt-5 border-t border-border pt-4 text-center">
            <button
              onClick={() => {
                setMode(mode === "login" ? "register" : "login");
                setError(null);
              }}
              className="text-small text-foreground-subtle hover:text-accent"
            >
              {mode === "login"
                ? "No account? Create a workspace"
                : "Already have an account? Sign in"}
            </button>
          </div>

          {config?.dev_mode && mode === "login" && (
            <div className="mt-5 rounded-md border border-border bg-surface-lowest p-3">
              <div className="mb-2 flex items-center gap-2">
                <Chip tone="warn">DEV MODE</Chip>
                <span className="font-mono text-mono-data text-foreground-faint">
                  seeded accounts
                </span>
              </div>
              <button
                type="button"
                onClick={() => {
                  setEmail("demo@kavachx.io");
                  setPassword("kavachx-demo-2024");
                }}
                className="term w-full text-left text-accent hover:underline"
              >
                demo@kavachx.io / kavachx-demo-2024 &nbsp;(OWNER)
              </button>
              <p className="mt-2 text-[11px] leading-4 text-foreground-faint">
                Role accounts share the same password: maintainer@, reviewer@, developer@,
                viewer@, auditor@kavachx.io — useful for seeing which roles may view a working
                exploit and which may publish.
              </p>
            </div>
          )}
        </div>

        <p className="mt-6 text-center text-[11px] leading-4 text-foreground-faint">
          Analyse only repositories and systems you are explicitly authorised to test.
        </p>
      </div>
    </main>
  );
}
