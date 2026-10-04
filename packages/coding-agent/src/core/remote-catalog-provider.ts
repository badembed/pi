import type { ModelType, Provider } from "@earendil-works/pi-ai";

export const REMOTE_CATALOG_REFRESH_INTERVAL_MS = 4 * 60 * 60 * 1000;
export const REMOTE_CATALOG_MODEL_TYPES: readonly ModelType[] = ["chat", "image", "classifier"];

/** Corporate Pi uses explicit local models; never restore remote catalog overlays. */
export function withRemoteCatalog(provider: Provider, _catalogBaseUrl?: string, _localGeneratedAt?: number): Provider {
	return provider;
}
