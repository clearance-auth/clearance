/**
 * Sample B2B app: real browser sign-up → dashboard (org auto-created) →
 * sign-out, against the live compose stack and its Postgres.
 */
import { expect, test } from "@playwright/test";

const SAMPLE_URL = process.env.CLEARANCE_SAMPLE_URL ?? "";

test.beforeAll(() => {
	if (!SAMPLE_URL) {
		throw new Error("CLEARANCE_SAMPLE_URL must be set (compose-smoke exports it)");
	}
});

test("unauthenticated dashboard redirects to sign-in", async ({ page }) => {
	await page.goto(`${SAMPLE_URL}/dashboard`);
	await expect(page).toHaveURL(/sign-in/);
});

test("browser sign-up reaches the dashboard with an auto-created workspace, and sign-out revokes access", async ({ page }) => {
	const email = `e2e-${Date.now().toString(36)}@compose.test`;
	const password = `E2e!${Math.random().toString(36).slice(2)}Aa1!`;

	await page.goto(`${SAMPLE_URL}/sign-up`);
	await page.locator('input[name="name"]').fill("Browser E2E");
	await page.locator('input[name="email"]').fill(email);
	await page.locator('input[name="password"]').fill(password);
	await page.locator('button[type="submit"]').click();

	await page.waitForURL(/dashboard/);
	await expect(page.getByTestId("protected-ok")).toContainText("Access granted");
	await expect(page.locator("body")).toContainText(email);
	// Org auto-creation on first dashboard load.
	await expect(page.locator("body")).toContainText(/workspace/i);

	// Sign out, then the dashboard must be gone.
	await page.getByRole("button", { name: "Sign out" }).click();
	await expect(page).toHaveURL(/sign-in/);
	await page.goto(`${SAMPLE_URL}/dashboard`);
	await expect(page).toHaveURL(/sign-in/);
});
