import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <div className="panel max-w-md p-8 text-center">
        <div className="font-mono text-mono-label uppercase text-accent">404</div>
        <h1 className="mt-3 text-headline-md">Nothing here</h1>
        <p className="mt-2 text-small text-foreground-muted">
          That page does not exist. It may have been a run that was never created, or a
          certificate that was never issued.
        </p>
        <Link href="/console" className="btn-secondary mt-6">
          Back to the console
        </Link>
      </div>
    </main>
  );
}
