# Infrastructure

This PoC deliberately ships **three services and nothing else**: PostgreSQL, the FastAPI backend, and
the Next.js console. See [`../docker-compose.yml`](../docker-compose.yml).

## What is deliberately absent

| Not here | Why |
| --- | --- |
| Kubernetes | Nothing in this PoC needs orchestration beyond Compose. |
| Redis | No queue and no cache is required. Runs are background asyncio tasks; the event bus is in-process with DB-backed replay as the cross-process source of truth. |
| Vector database | **The specification avoids one on purpose.** KavachX's information is keyed and relational — run → finding → patch → evidence node — and every lookup is by id, ref or scope. Similarity search would add a dependency and answer no question the system asks. |
| Object storage | Artifacts are text (certificates, diffs, markdown) and live in PostgreSQL with a content hash. |
| Message broker | Discovery channels fan out with `asyncio.gather` inside one run. |

Adding any of these would be architecture for its own sake.

## Files here

| File | Purpose |
| --- | --- |
| `postgres/init.sql` | Optional first-boot SQL. Migrations own the schema; this is for extensions and roles. |
| `gvisor/README.md` | Installing gVisor and registering `runsc` with Docker. |
| `prometheus/prometheus.yml` | Scrape config for `/metrics`. |

## Production shape

If this were to run beyond a laptop, the shape that follows from the architecture:

```
              ┌──────────────┐
   TLS ──────▶│  console     │  Next.js, static + server bundle
              └──────┬───────┘
                     │ /api
              ┌──────▼───────┐
   TLS ──────▶│  api         │  N replicas, stateless
              └──────┬───────┘
                     │
        ┌────────────┼────────────────┐
        ▼            ▼                ▼
  ┌──────────┐ ┌───────────┐  ┌──────────────┐
  │ postgres │ │ orchestr. │  │  publisher   │
  │  (RLS)   │ │ workers   │  │  (isolated)  │
  └──────────┘ └─────┬─────┘  └──────────────┘
                     │             ▲
                     ▼             │ verified patch + certificate
              ┌──────────────┐     │  (data only, no live objects)
              │ gVisor pool  │─────┘
              │ HOSTILE CODE │
              └──────────────┘
```

Three changes that matter most:

1. **Split the publisher into its own deployment.** In this build it is a module the API calls; in
   production it should be a separate service with the GitHub credential mounted only there, so the
   process running alongside the sandbox pool cannot reach it even in principle.
2. **Give the API a non-owner database role** and enable `FORCE ROW LEVEL SECURITY` with a per-checkout
   `SET kavachx.tenant_id`. Migration `0002_rls` already creates the policies; see
   [`../docs/HONESTY.md`](../docs/HONESTY.md) §5 for why they are currently inert for the app's own
   connection.
3. **Run the sandbox on dedicated hosts** with gVisor or Firecracker, no outbound network route at the
   VPC level, and no instance metadata access. Belt and braces: the adapter already denies the
   network, but a second layer at the network boundary costs nothing.

Also: a real pub/sub for the live SSE tail if the API runs multiple workers (replay is already
DB-backed and correct), and an asymmetric certificate signature with a published verification key.
