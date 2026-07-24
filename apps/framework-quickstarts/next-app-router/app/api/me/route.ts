import { NextResponse } from "next/server";
import { ClearanceVerificationError } from "@clearance/verification";
import { bearerToken, verifier } from "../../../lib/verifier";

export async function GET(request: Request): Promise<NextResponse> {
	const token = bearerToken(request.headers.get("authorization"));
	if (!token) {
		return NextResponse.json({ error: "missing_bearer_token" }, { status: 401 });
	}

	try {
		return NextResponse.json(await verifier.verify(token));
	} catch (error) {
		const code = error instanceof ClearanceVerificationError ? error.code : "verification_failed";
		return NextResponse.json({ error: code }, { status: 401 });
	}
}
