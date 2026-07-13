import { scryptSync } from "node:crypto";

export function hashPassword(password: string, salt: string): string {
	return scryptSync(password, salt, 32).toString("hex");
}
