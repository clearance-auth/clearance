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
const readonlyQueryValues = ["active", 10] as const;

async function assertPublicCompatibility(): Promise<void> {
	await bundle.auth.api.signInEmail({});
	await bundle.auth.api.getSession({});
	await bundle.auth.api.resetPassword({});

	const { rows, rowCount } = await bundle.pool.query(
		"select * from users where status = $1 limit $2",
		readonlyQueryValues,
	);
	void rows;
	void rowCount;
}

void rootContract;
void clearanceContract;
void clientContract;
void nodeContract;
void secretPolicyContract;
void assertPublicCompatibility;
