import { headers } from "next/headers";
import { bearerToken, verifier } from "../../lib/verifier";

export default async function ServerClaimsPage() {
	const requestHeaders = await headers();
	const token = bearerToken(requestHeaders.get("authorization"));
	const claims = token ? await verifier.verify(token).catch(() => null) : null;

	return (
		<main>
			<h1>Server component verification</h1>
			<p>
				{claims
					? `Verified ${claims.kind}: ${claims.sub}`
					: "Send a valid Authorization: Bearer header to verify this request."}
			</p>
		</main>
	);
}
