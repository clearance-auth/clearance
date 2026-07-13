/**
 * Console: real browser completes login → overview → users → sign-out.
 * Reintroducing the audited bug (login form removed / unwired) turns these
 * red — the original blind spot is structurally impossible now.
 */
import { expect, test } from "@playwright/test";

const CONSOLE_URL = process.env.CLEARANCE_CONSOLE_URL ?? "";
const ADMIN_USER = process.env.CLEARANCE_CONSOLE_ADMIN_USER ?? "";
const ADMIN_PASSWORD = process.env.CLEARANCE_CONSOLE_ADMIN_PASSWORD ?? "";

test.beforeAll(() => {
	if (!CONSOLE_URL || !ADMIN_USER || !ADMIN_PASSWORD) {
		throw new Error(
			"CLEARANCE_CONSOLE_URL / CLEARANCE_CONSOLE_ADMIN_USER / CLEARANCE_CONSOLE_ADMIN_PASSWORD must be set (compose-smoke exports them)",
		);
	}
});

test("unauthenticated console shows the login form, not data surfaces", async ({ page }) => {
	await page.goto(`${CONSOLE_URL}/overview`);
	await expect(page.getByTestId("console-login")).toBeVisible();
	await expect(page.locator(".app")).toBeHidden();
});

test("wrong password shows a structured error and stays on login", async ({ page }) => {
	await page.goto(CONSOLE_URL);
	await page.locator("#login-username").fill(ADMIN_USER);
	await page.locator("#login-password").fill("definitely-wrong-password");
	await page.locator("#login-submit").click();
	await expect(page.locator("#login-error")).toBeVisible();
	await expect(page.getByTestId("console-login")).toBeVisible();
});

test("login renders Overview with live data, then Users, then sign-out returns to login", async ({ page }) => {
	await page.goto(CONSOLE_URL);
	await page.locator("#login-username").fill(ADMIN_USER);
	await page.locator("#login-password").fill(ADMIN_PASSWORD);
	await page.locator("#login-submit").click();

	await expect(page.locator(".app")).toBeVisible();
	await expect(page.locator("#view")).toContainText("Total users");
	const signout = page.getByTestId("console-signout");
	await expect(signout).toBeVisible();
	await expect(signout).toContainText(ADMIN_USER);

	await page.locator('.rail button[data-route="users"]').click();
	await expect(page.locator("#page-title")).toHaveText("Users");
	// The compose smoke created ops@compose.test before this suite runs.
	await expect(page.locator("#view")).toContainText("ops@compose.test");

	await signout.click();
	await expect(page.getByTestId("console-login")).toBeVisible();
	await expect(page.locator(".app")).toBeHidden();
});
