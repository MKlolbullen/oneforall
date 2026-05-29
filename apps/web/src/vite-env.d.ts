/// <reference types="vite/client" />

declare module '*.css';

interface ReconForgeRuntimeConfig {
  apiBaseUrl?: string;
  wsBaseUrl?: string;
}

interface Window {
  __RECONFORGE_CONFIG__?: ReconForgeRuntimeConfig;
}

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_WS_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
