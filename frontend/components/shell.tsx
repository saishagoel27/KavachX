"use client";

import {
  Activity,
  ChevronDown,
  FileCheck2,
  FolderGit2,
  LayoutDashboard,
  LogOut,
  Menu,
  Play,
  ScrollText,
  ShieldCheck,
  Sliders,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { ApiError, endpoints, type Me, tokens } from "@/lib/api";

import { Chip, cn, Spinner } from "./ui";

const NAV = [
  { href: "/console", label: "Dashboard", icon: LayoutDashboard },
  { href: "/console/runs", label: "Runs", icon: Activity },
  { href: "/console/projects", label: "Projects", icon: FolderGit2 },
  { href: "/console/certificates", label: "Certificates", icon: FileCheck2 },
  { href: "/console/audit", label: "Audit", icon: ScrollText },
  { href: "/console/settings", label: "Settings", icon: Sliders },
];

export function useMe() {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const router = useRouter();

  const load = useCallback(async () => {
    if (!tokens.access()) {
      router.replace("/login");
      return;
    }
    try {
      setMe(await endpoints.me());
    } catch (exc) {
      if (exc instanceof ApiError && (exc.status === 401 || exc.status === 403)) {
        tokens.clear();
        router.replace("/login");
        return;
      }
      setError(exc instanceof Error ? exc.message : "Could not load the session.");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    void load();
  }, [load]);

  return { me, loading, error, reload: load };
}

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { me, loading } = useMe();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [orgOpen, setOrgOpen] = useState(false);

  const signOut = async () => {
    try {
      await endpoints.logout();
    } catch {
      /* signing out locally matters more than the server round-trip succeeding */
    }
    tokens.clear();
    router.replace("/login");
  };

  const switchOrg = async (organisationId: string) => {
    const pair = await endpoints.switchOrg(organisationId);
    tokens.set(pair.access_token, pair.refresh_token);
    setOrgOpen(false);
    // A full reload is correct here: every panel is tenant-scoped and must be refetched.
    window.location.reload();
  };

  const active = me?.memberships.find((m) => m.organisation_id === me.active_organisation_id);

  return (
    <div className="flex min-h-screen bg-background">
      {/* Sidebar — collapses to a drawer on small screens rather than reflowing the
          information-dense main area. */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-border bg-surface-lowest",
          "transition-transform duration-200 lg:translate-x-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-14 items-center justify-between border-b border-border px-4">
          <Link href="/" className="flex items-center gap-2.5">
            <ShieldCheck className="h-5 w-5 text-accent" />
            <span className="font-mono text-sm font-bold tracking-[0.2em]">KAVACHX</span>
          </Link>
          <button
            onClick={() => setMobileOpen(false)}
            className="lg:hidden"
            aria-label="Close navigation"
          >
            <X className="h-4 w-4 text-foreground-subtle" />
          </button>
        </div>

        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map((item) => {
            const isActive =
              item.href === "/console"
                ? pathname === "/console"
                : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-accent/10 text-accent"
                    : "text-foreground-muted hover:bg-surface-high hover:text-foreground",
                )}
              >
                <item.icon className="h-4 w-4 shrink-0" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="border-t border-border p-2">
          <Link
            href="/console/runs/new"
            onClick={() => setMobileOpen(false)}
            className="btn-primary w-full text-xs"
          >
            <Play className="h-3.5 w-3.5" />
            New Security Run
          </Link>
        </div>

        <div className="border-t border-border p-3">
          {loading ? (
            <Spinner />
          ) : (
            <>
              <button
                onClick={() => setOrgOpen((v) => !v)}
                className="flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5
                  text-left hover:bg-surface-high"
                aria-expanded={orgOpen}
              >
                <div className="min-w-0">
                  <div className="truncate text-small text-foreground">
                    {active?.organisation_name ?? "No organisation"}
                  </div>
                  <div className="font-mono text-[10px] uppercase tracking-wider text-foreground-faint">
                    {me?.active_role ?? "—"}
                  </div>
                </div>
                <ChevronDown className="h-3.5 w-3.5 shrink-0 text-foreground-faint" />
              </button>

              {orgOpen && me && me.memberships.length > 1 && (
                <div className="mt-1 space-y-0.5 rounded-md border border-border bg-surface p-1">
                  {me.memberships.map((membership) => (
                    <button
                      key={membership.organisation_id}
                      onClick={() => void switchOrg(membership.organisation_id)}
                      className={cn(
                        "block w-full truncate rounded px-2 py-1.5 text-left text-small",
                        membership.organisation_id === me.active_organisation_id
                          ? "text-accent"
                          : "text-foreground-muted hover:bg-surface-high",
                      )}
                    >
                      {membership.organisation_name}
                      <span className="ml-1.5 font-mono text-[10px] text-foreground-faint">
                        {membership.role}
                      </span>
                    </button>
                  ))}
                </div>
              )}

              <div className="mt-2 flex items-center justify-between gap-2 px-2">
                <span className="truncate text-[11px] text-foreground-faint" title={me?.user.email}>
                  {me?.user.email}
                </span>
                <button
                  onClick={() => void signOut()}
                  className="text-foreground-faint hover:text-refuted"
                  title="Sign out"
                  aria-label="Sign out"
                >
                  <LogOut className="h-3.5 w-3.5" />
                </button>
              </div>
            </>
          )}
        </div>
      </aside>

      {mobileOpen && (
        <button
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-label="Close navigation overlay"
        />
      )}

      <div className="flex min-w-0 flex-1 flex-col lg:pl-60">
        <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-border bg-background/85 px-4 backdrop-blur">
          <button
            onClick={() => setMobileOpen(true)}
            className="lg:hidden"
            aria-label="Open navigation"
          >
            <Menu className="h-5 w-5 text-foreground-subtle" />
          </button>
          <Breadcrumb pathname={pathname} />
          <div className="ml-auto">
            <SandboxIndicator />
          </div>
        </header>
        <main className="min-w-0 flex-1 p-4 sm:p-6">{children}</main>
      </div>
    </div>
  );
}

function Breadcrumb({ pathname }: { pathname: string }) {
  const parts = pathname.split("/").filter(Boolean).slice(1);
  return (
    <div className="flex min-w-0 items-center gap-2 font-mono text-mono-label uppercase text-foreground-subtle">
      <span className="text-accent">CONSOLE</span>
      {parts.map((part, index) => (
        <span key={index} className="flex min-w-0 items-center gap-2">
          <span className="text-foreground-faint">/</span>
          <span className="truncate">{part.length > 12 ? `${part.slice(0, 8)}…` : part}</span>
        </span>
      ))}
    </div>
  );
}

/**
 * Reports the active execution boundary in the header, permanently.
 *
 * The development adapter is not an isolation boundary, and a console that shows an unqualified
 * green light while running on it would be misleading in exactly the way this product exists to
 * avoid. So the warning lives in the chrome, not in a dismissible toast.
 */
function SandboxIndicator() {
  const [info, setInfo] = useState<{ adapter: string; safe: boolean; note: string } | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const data = await endpoints.sandboxInfo();
        const active = data.active_capabilities ?? {};
        setInfo({
          adapter: String(data.configured ?? "unknown"),
          safe: Boolean(active.suitable_for_untrusted_code),
          note: String(active.notes ?? ""),
        });
      } catch {
        /* the indicator is informational; failing to load it must not break the header */
      }
    })();
  }, []);

  if (!info) return null;

  return (
    <div className="flex items-center gap-2" title={info.note}>
      <Chip tone={info.safe ? "verified" : "warn"}>
        SANDBOX {info.adapter}
        {!info.safe && " · dev only"}
      </Chip>
      <Chip tone="verified" className="hidden sm:inline-flex">
        EGRESS 0 B
      </Chip>
    </div>
  );
}
