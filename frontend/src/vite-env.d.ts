/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Backend API root, e.g. http://127.0.0.1:8000.
   * Set it to an empty string to use same-origin paths proxied by the vite
   * dev server (see vite.config.ts).
   */
  readonly VITE_API_BASE_URL: string;
  /** Optional bearer token, used when AUTH_REQUIRED=true on the backend. */
  readonly VITE_API_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
