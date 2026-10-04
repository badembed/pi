import type { FetchFunction } from "@earendil-works/pi-ai";
import type { CorporateNetworkPolicy } from "./corporate-network-policy.ts";

export function corporateFetch(
	policy: CorporateNetworkPolicy,
	transport: FetchFunction,
	provider?: string,
): FetchFunction {
	return async (input, init) => {
		const address = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
		if (provider) policy.assertModel(provider, address);
		else policy.assertNetwork(address);
		const response = await transport(input, { ...init, redirect: "manual" });
		if (response.status >= 300 && response.status < 400) {
			await response.body?.cancel();
			throw new Error("Corporate model transport does not follow redirects.");
		}
		return response;
	};
}
