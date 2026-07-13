import type { CookieOptions } from "@clearance/call";

export type ClearanceCookie = { name: string; attributes: CookieOptions };

export type ClearanceCookies = {
	sessionToken: ClearanceCookie;
	sessionData: ClearanceCookie;
	accountData: ClearanceCookie;
	dontRememberToken: ClearanceCookie;
};
