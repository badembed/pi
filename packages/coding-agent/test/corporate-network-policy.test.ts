import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Api, FetchFunction, Model } from "@earendil-works/pi-ai";
import { describe, expect, it, vi } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { corporateFetch } from "../src/core/corporate-fetch.ts";
import { CorporateNetworkPolicy, loadCorporateNetworkPolicy } from "../src/core/corporate-network-policy.ts";
import { restoreModelFromSession } from "../src/core/model-resolver.ts";
import { ModelRuntime } from "../src/core/model-runtime.ts";
import { withRemoteCatalog } from "../src/core/remote-catalog-provider.ts";

const origin = "https://llm.company.test";
const policy = () => new CorporateNetworkPolicy({ providers: { corporate: { modelOrigins: [origin] } } });

async function runtimeWithModel(api: Api = "openai-completions") {
	const credentials = AuthStorage.inMemory();
	const runtime = await ModelRuntime.create({
		credentials,
		modelsPath: null,
		networkPolicy: policy(),
	});
	runtime.registerProvider("corporate", {
		baseUrl: `${origin}/v1`,
		api,
		apiKey: "synthetic-key",
		models: [
			{
				id: "corporate-model",
				name: "Corporate",
				reasoning: false,
				input: ["text"],
				contextWindow: 8192,
				maxTokens: 1024,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			},
		],
	});
	await runtime.refresh({ allowNetwork: false });
	const model = runtime.getModel("corporate", "corporate-model");
	if (!model) throw new Error("Test corporate model missing");
	return { runtime, model, credentials };
}

function responseFor(api: Api): Response {
	const events =
		api === "anthropic-messages"
			? [
					{ type: "message_start", message: { id: "test", usage: { input_tokens: 1, output_tokens: 0 } } },
					{ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
					{ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "ok" } },
					{ type: "content_block_stop", index: 0 },
					{ type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 1 } },
					{ type: "message_stop" },
				]
			: [
					{ type: "response.created", response: { id: "test" } },
					{
						type: "response.output_item.added",
						output_index: 0,
						item: { type: "message", id: "msg", role: "assistant", content: [] },
					},
					{ type: "response.output_text.delta", output_index: 0, content_index: 0, item_id: "msg", delta: "ok" },
					{
						type: "response.output_item.done",
						output_index: 0,
						item: {
							type: "message",
							id: "msg",
							role: "assistant",
							status: "completed",
							content: [{ type: "output_text", text: "ok", annotations: [] }],
						},
					},
					{
						type: "response.completed",
						response: { id: "test", status: "completed", usage: { input_tokens: 1, output_tokens: 1 } },
					},
				];
	return new Response(events.map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join(""), {
		headers: { "Content-Type": "text/event-stream" },
	});
}

describe("corporate network policy", () => {
	it("binds exact origins to providers and rejects lookalike hosts and credential URLs", () => {
		const rules = policy();
		expect(rules.allowsModel("corporate", `${origin}/v1/chat/completions`)).toBe(true);
		for (const address of [
			"https://llm.company.test.attacker.test/v1",
			"https://llm.company.test:8443/v1",
			"https://secret@llm.company.test/v1",
			"http://llm.company.test/v1",
		]) {
			expect(rules.allowsModel("corporate", address)).toBe(false);
		}
		expect(rules.allowsModel("other", origin)).toBe(false);
	});

	it("rejects malformed policy and insecure remote origins", () => {
		for (const config of [
			null,
			{ providers: [] },
			{ providers: { corporate: { modelOrigins: ["http://remote.test"] } } },
			{ providers: { corporate: { modelOrigins: [origin], disabled: true } } },
		]) {
			expect(() => new CorporateNetworkPolicy(config)).toThrow();
		}
	});

	it("denies all model requests when the policy file is absent", () => {
		const rules = loadCorporateNetworkPolicy(join(tmpdir(), "pi-nonexistent-policy", "network-policy.json"));
		expect(rules.allowsModel("openai", "https://api.openai.com/v1")).toBe(false);
	});

	it("blocks the actual transport destination before invoking fetch", async () => {
		const transport = vi.fn<FetchFunction>();
		await expect(
			corporateFetch(
				policy(),
				transport,
				"corporate",
			)("https://external.test/v1", { body: "synthetic-secret", method: "POST" }),
		).rejects.toThrow("blocks");
		expect(transport).not.toHaveBeenCalled();
	});

	it("does not follow redirects or forward secrets to their target", async () => {
		const transport = vi
			.fn<FetchFunction>()
			.mockResolvedValue(
				new Response(null, { status: 307, headers: { Location: "https://external.test/collect" } }),
			);
		await expect(
			corporateFetch(
				policy(),
				transport,
				"corporate",
			)(`${origin}/v1`, {
				method: "POST",
				body: "synthetic-secret",
				headers: { Authorization: "Bearer synthetic-key" },
			}),
		).rejects.toThrow("does not follow redirects");
		expect(transport).toHaveBeenCalledTimes(1);
		expect(transport.mock.calls[0]?.[1]?.redirect).toBe("manual");
	});

	it("keeps approved model streaming functional with a synthetic transport", async () => {
		const { runtime, model } = await runtimeWithModel();
		const transport = vi
			.fn<FetchFunction>()
			.mockResolvedValue(
				new Response(
					[
						'data: {"id":"test","choices":[{"index":0,"delta":{"role":"assistant","content":"ok"},"finish_reason":null}]}',
						'data: {"id":"test","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}',
						"data: [DONE]",
						"",
						"",
					].join("\n\n"),
					{ headers: { "Content-Type": "text/event-stream" } },
				),
			);
		const result = await runtime.completeSimple(
			model,
			{ messages: [{ role: "user", content: "synthetic context", timestamp: 0 }] },
			{ fetch: transport },
		);
		expect(result.stopReason).toBe("stop");
		expect(result.content).toContainEqual({ type: "text", text: "ok" });
		expect(transport).toHaveBeenCalledTimes(1);
	});

	it("rejects a tampered model before auth resolution or transport", async () => {
		const { runtime, model, credentials } = await runtimeWithModel();
		const auth = vi.spyOn(credentials, "read");
		const transport = vi.fn<FetchFunction>();
		const result = await runtime.completeSimple(
			{ ...model, baseUrl: "https://external.test/v1" },
			{ messages: [] },
			{ fetch: transport },
		);
		expect(result.stopReason).toBe("error");
		expect(transport).not.toHaveBeenCalled();
		expect(auth).not.toHaveBeenCalled();
	});

	it.each(["openai-responses", "anthropic-messages", "azure-openai-responses"] as const)(
		"streams %s through the policy wrapper",
		async (api) => {
			const { runtime, model } = await runtimeWithModel(api);
			const transport = vi.fn<FetchFunction>(async () => responseFor(api));
			const result = await runtime.completeSimple(
				model,
				{ messages: [{ role: "user", content: "synthetic context", timestamp: 0 }] },
				{
					fetch: transport,
					maxRetries: 0,
					env: { AZURE_OPENAI_BASE_URL: `${origin}/v1`, AZURE_OPENAI_RESOURCE_NAME: "" },
				},
			);
			expect(result.errorMessage).toBeUndefined();
			expect(result.stopReason).toBe("stop");
			expect(result.content).toContainEqual(expect.objectContaining({ type: "text", text: "ok" }));
			expect(transport).toHaveBeenCalledTimes(1);
			const destination = transport.mock.calls[0]?.[0];
			const url =
				typeof destination === "string"
					? destination
					: destination instanceof URL
						? destination.href
						: destination?.url;
			expect(url).toMatch(/^https:\/\/llm\.company\.test\//);
			expect(transport.mock.calls[0]?.[1]?.redirect).toBe("manual");
		},
	);

	it("blocks Azure's environment destination override before transport", async () => {
		const { runtime, model } = await runtimeWithModel("azure-openai-responses");
		const transport = vi.fn<FetchFunction>();
		const result = await runtime.completeSimple(
			model,
			{ messages: [] },
			{ fetch: transport, maxRetries: 0, env: { AZURE_OPENAI_BASE_URL: "https://external.test/v1" } },
		);
		expect(result.stopReason).toBe("error");
		expect(transport).not.toHaveBeenCalled();
	});

	it("blocks an endpoint replaced during auth resolution before transport", async () => {
		const { runtime, model } = await runtimeWithModel();
		const provider = runtime.getProvider("corporate");
		if (!provider) throw new Error("Missing provider");
		runtime.registerNativeProvider({
			...provider,
			auth: {
				apiKey: {
					...provider.auth.apiKey,
					name: "Synthetic",
					resolve: async () => ({
						auth: { apiKey: "synthetic-key", baseUrl: "https://external.test/v1" },
						source: "test",
					}),
				},
			},
		});
		const transport = vi.fn<FetchFunction>();
		const result = await runtime.completeSimple(model, { messages: [] }, { fetch: transport });
		expect(result.stopReason).toBe("error");
		expect(transport).not.toHaveBeenCalled();
	});

	it("fails closed for an unverified transport", async () => {
		const { runtime, model } = await runtimeWithModel("google-generative-ai");
		const transport = vi.fn<FetchFunction>();
		const result = await runtime.completeSimple(model, { messages: [] }, { fetch: transport });
		expect(result.stopReason).toBe("error");
		expect(result.errorMessage).toContain("has not been verified");
		expect(transport).not.toHaveBeenCalled();
	});

	it("excludes public models despite stored public credentials and session history", async () => {
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory({ openai: { type: "api_key", key: "synthetic-public-key" } }),
			modelsPath: null,
			networkPolicy: policy(),
		});
		expect(runtime.getModels()).toEqual([]);
		expect(runtime.getAvailableSnapshot()).toEqual([]);
		expect((await restoreModelFromSession("openai", "gpt-5.5", undefined, false, runtime)).model).toBeUndefined();
	});

	it("throws on an invalid corporate override instead of retaining the public provider", async () => {
		const directory = await mkdtemp(join(tmpdir(), "pi-corporate-policy-"));
		try {
			const path = join(directory, "models.json");
			await writeFile(
				path,
				JSON.stringify({
					providers: { openai: { baseUrl: `${origin}/v1`, models: [{ id: "invalid", maxTokens: 0 }] } },
				}),
			);
			await expect(
				ModelRuntime.create({ credentials: AuthStorage.inMemory(), modelsPath: path, networkPolicy: policy() }),
			).rejects.toThrow("invalid maxTokens");
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	});

	it("ignores old remote overlays, including when refresh explicitly permits network", async () => {
		const { runtime, model } = await runtimeWithModel();
		const provider = runtime.getProvider("corporate");
		if (!provider) throw new Error("Missing test provider");
		const wrapped = withRemoteCatalog(provider, "https://external.test");
		expect(wrapped.getModels()).toContainEqual(model as Model<"openai-completions">);
		expect(wrapped.refreshModels).toBeUndefined();
	});
});
