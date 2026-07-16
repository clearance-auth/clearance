import { expect, test } from "@playwright/test";

test("same-origin passkey option POST carries the browser-controlled Origin header", async ({
	page,
}) => {
	let ceremonyRequest:
		| { method: string; origin: string | undefined }
		| undefined;

	await page.route("https://auth.example.test/**", async (route) => {
		const request = route.request();
		if (request.resourceType() === "document") {
			await route.fulfill({
				contentType: "text/html",
				body: "<!doctype html><title>Passkey origin proof</title>",
			});
			return;
		}
		ceremonyRequest = {
			method: request.method(),
			origin: request.headers().origin,
		};
		await route.fulfill({
			contentType: "application/json",
			body: JSON.stringify({ ok: true }),
		});
	});

	await page.goto("https://auth.example.test/");
	await page.evaluate(async () => {
		await fetch("/api/auth/passkey/generate-authentication-options", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: "{}",
		});
	});

	expect(ceremonyRequest).toEqual({
		method: "POST",
		origin: "https://auth.example.test",
	});
});
