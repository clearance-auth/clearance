/**
 * Keep the generated product declarations honest without publishing the
 * inherited runtime's internal declaration graph.
 */
type PublicRoot = typeof import("./public-types/index.js");
type ImplementationRoot = typeof import("./index.js");

// The low-level runtime's generic API cannot prove a string index even though
// its exposed API values are callable endpoints. The public declaration keeps
// that historical compatibility surface without publishing the internal type graph.
const rootContract: Omit<PublicRoot, "clearance"> =
	{} as Omit<ImplementationRoot, "clearance">;
const clearanceContract: Pick<
	ReturnType<PublicRoot["clearance"]>,
	"handler" | "$context"
> = {} as Pick<
	ReturnType<ImplementationRoot["clearance"]>,
	"handler" | "$context"
>;
const clientContract: typeof import("./public-types/client.js") =
	{} as typeof import("./client.js");
const nodeContract: typeof import("./public-types/node.js") =
	{} as typeof import("./node.js");
const secretPolicyContract: typeof import("./public-types/secret-policy.js") =
	{} as typeof import("./secret-policy.js");

declare const bundle: import("./public-types/index.js").ClearanceAuthBundle;
const managedPolicyOptions: import("./public-types/index.js").CreateClearanceAuthOptions = {
	baseURL: "https://auth.example.test",
	secret: "public-contract-secret-value!!",
	databaseUrl: "postgres://example.invalid/clearance",
	authenticationPolicy: {
		projectId: "project_public_contract",
		environmentId: "environment_public_contract",
	},
};
const readonlyQueryValues = ["active", 10] as const;
const publicPolicy: import("./public-types/index.js").ClearanceAuthenticationPolicy = {
	passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	factorLockout: { enabled: true, maxFailedAttempts: 5, durationSeconds: 600 },
	minimumAssurance: "single_factor",
	allowedFactors: { totp: true, passkey: true },
	trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
	assuranceMaxAgeSeconds: null,
};

async function assertPublicCompatibility(): Promise<void> {
	await bundle.auth.api.signInEmail({});
	const session = await bundle.auth.api.getSession({});
	if (session) {
		void session.session.id;
		const deprecatedNonSecretHandle: string = session.session.token;
		void deprecatedNonSecretHandle;
	}
	await bundle.auth.api.resetPassword({});

	const { rows, rowCount } = await bundle.pool.query(
		"select * from users where status = $1 limit $2",
		readonlyQueryValues,
	);
	void rows;
	void rowCount;

	if (bundle.authenticationPolicy) {
		void bundle.authenticationPolicy.scope.projectId;
		void bundle.authenticationPolicy.scope.environmentId;
		const current = await bundle.authenticationPolicy.get();
		const plan = await bundle.authenticationPolicy.plan({ policy: publicPolicy });
		await bundle.authenticationPolicy.apply({
			policy: plan.candidate.policy as import("./public-types/index.js").ClearanceAuthenticationPolicy,
			expectedRevision: current.revision,
		});
		await bundle.authenticationPolicy.plan({
			organizationId: "organization_public_contract",
			policy: { minimumAssurance: "multi_factor" },
		});
		await bundle.authenticationPolicy.plan({
			organizationId: "organization_public_contract",
			policy: null,
		});
		const unlock = await bundle.authenticationPolicy.planUnlock({
			userId: "user_public_contract",
			kind: "all",
		});
		void unlock.password.matchedRows;
	}
}

void rootContract;
void clearanceContract;
void clientContract;
void nodeContract;
void secretPolicyContract;
void managedPolicyOptions;
void assertPublicCompatibility;
