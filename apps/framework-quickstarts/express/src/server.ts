import express, { type NextFunction, type Request, type Response } from "express";
import { ClearanceVerificationError, type ClearanceVerifiedClaims } from "@clearance/verification";
import { bearerToken, verifier } from "./verifier.js";

const app = express();
const port = Number(process.env.PORT ?? 3000);

declare global {
	namespace Express {
		interface Locals {
			claims?: ClearanceVerifiedClaims;
		}
	}
}

async function requireClearanceToken(
	request: Request,
	response: Response,
	next: NextFunction,
): Promise<void> {
	const token = bearerToken(request.header("authorization") ?? undefined);
	if (!token) {
		response.status(401).json({ error: "missing_bearer_token" });
		return;
	}

	try {
		response.locals.claims = await verifier.verify(token);
		next();
	} catch (error) {
		const code = error instanceof ClearanceVerificationError ? error.code : "verification_failed";
		response.status(401).json({ error: code });
	}
}

app.get("/me", requireClearanceToken, (_request, response) => {
	response.json(response.locals.claims);
});

app.listen(port, () => {
	console.log(`Express quickstart listening on http://localhost:${port}`);
});
