/** Compile-only contract for the stable authentication-security product facade. */
declare const clientModule: typeof import("./public-types/client.js");
declare const productModule: typeof import("./public-types/index.js");
declare const bundle: import("./public-types/index.js").ClearanceAuthBundle;

async function assertAuthenticationSecurityPublicTypes(): Promise<void> {
	const twoFactorOnly = clientModule.createAuthClient({
		plugins: [
			clientModule.twoFactorClient({
				onTwoFactorRedirect: async ({ twoFactorMethods }) => {
					void twoFactorMethods;
				},
			}),
		],
	});
	const enrollment = await twoFactorOnly.twoFactor.enable({
		password: "password",
		currentCode: "123456",
	});
	void enrollment.data?.totpURI;
	await twoFactorOnly.twoFactor.getTotpUri({ password: "password" });
	await twoFactorOnly.twoFactor.verifyTotp({ code: "123456" });
	await twoFactorOnly.twoFactor.generateBackupCodes({
		password: "password",
		currentCode: "123456",
	});
	await twoFactorOnly.twoFactor.verifyBackupCode({ code: "backup-code" });
	await twoFactorOnly.twoFactor.disable({
		password: "password",
		recoveryCode: "backup-code",
	});

	const jwtOnly = clientModule.createAuthClient({
		plugins: [clientModule.jwtClient()],
	});
	void (await jwtOnly.token()).data?.token;
	void (await jwtOnly.jwks()).data?.keys[0]?.kid;

	const headers = new Headers();
	const signup = await bundle.auth.api.signUpEmail({
		body: { email: "user@example.com", password: "password", name: "User" },
	});
	void signup.token;
	await bundle.auth.api.enableTwoFactor({
		body: { password: "password", currentCode: "123456" },
		headers,
	});
	await bundle.auth.api.getTOTPURI({ body: { password: "password" }, headers });
	await bundle.auth.api.verifyTOTP({ body: { code: "123456" }, headers });
	await bundle.auth.api.generateBackupCodes({
		body: { password: "password", currentCode: "123456" },
		headers,
	});
	await bundle.auth.api.verifyBackupCode({
		body: { code: "backup-code" },
		headers,
	});
	await bundle.auth.api.disableTwoFactor({
		body: { password: "password", recoveryCode: "backup-code" },
		headers,
	});
	const token = await bundle.auth.api.getToken({ headers });
	void (await bundle.auth.api.verifyJWT({ body: { token: token.token } }))
		.payload;
	void (await bundle.auth.api.getJwks()).keys[0]?.alg;

	const disabled = productModule.createClearanceAuth({
		baseURL: "https://example.com",
		secret: "compile-only-secret",
		databaseUrl: "postgres://compile-only",
		authenticationSecurity: {
			twoFactor: { enabled: false },
			asymmetricAccessTokens: { enabled: false },
		},
	});
	// @ts-expect-error disabled two-factor endpoints are omitted from the server API
	void disabled.auth.api.enableTwoFactor;
	// @ts-expect-error disabled JWT endpoints are omitted from the server API
	void disabled.auth.api.getToken;

	const dynamicSecurity: import("./public-types/index.js").ClearanceAuthenticationSecurityOptions =
		Math.random() > 0.5
			? { twoFactor: { enabled: false } }
			: { asymmetricAccessTokens: { enabled: false } };
	const dynamic = productModule.createClearanceAuth({
		baseURL: "https://example.com",
		secret: "compile-only-secret",
		databaseUrl: "postgres://compile-only",
		authenticationSecurity: dynamicSecurity,
	});
	// @ts-expect-error dynamically disabled endpoints require presence narrowing
	await dynamic.auth.api.enableTwoFactor({
		body: { password: "password" },
		headers,
	});
}

void assertAuthenticationSecurityPublicTypes;
