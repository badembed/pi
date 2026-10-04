type FetchInput = Parameters<typeof fetch>[0];

export interface FetchRetryOptions {
	/** Number of additional attempts after the initial request. Defaults to two. */
	maxRetries?: number;
	/** Retry transient HTTP responses as well as transport failures. Defaults to true. */
	retryOnStatus?: boolean;
	/** Overall time budget shared by all attempts. */
	timeoutMs?: number;
	/** Per-attempt timeout. A new timeout is created for every attempt. */
	attemptTimeoutMs?: number;
}

/** Corporate builds disable management traffic independently of model traffic. */
export async function fetchWithRetry(
	_input: FetchInput,
	_init: RequestInit | undefined = undefined,
	_options: FetchRetryOptions = {},
): Promise<Response> {
	throw new Error("Management network requests are disabled in corporate Pi.");
}
