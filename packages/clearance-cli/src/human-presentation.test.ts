import { describe, expect, it } from "vitest";
import { renderHumanPresentation, renderResponsiveTable } from "./human-presentation.js";

describe("human presentation", () => {
	it("renders wide tables and switches to labeled rows when narrow", () => {
		const columns = [{ key: "email", label: "Email", minWidth: 12 }, { key: "status", label: "Status", minWidth: 8 }];
		const rows = [{ email: "zoe@example.com", status: "active" }];
		expect(renderResponsiveTable(columns, rows, 40)).toContain("Email");
		expect(renderResponsiveTable(columns, rows, 20)).toContain("Email: zoe@example");
	});

	it("renders safe list, detail, mutation receipts, empty states, groups, actions, and JSON discovery", () => {
		const list = renderHumanPresentation({ kind: "list", title: "Users\u001b[31m", columns: [{ key: "name", label: "Name" }], rows: [], empty: "No users", next: ["Create a user"], rawJsonCommand: "clearance users list --output-format json" });
		expect(list).toContain("Users");
		expect(list).toContain("No users");
		expect(list).toContain("Raw JSON:");
		const detail = renderHumanPresentation({ kind: "detail", title: "User", fields: [{ group: "Identity", label: "Email", value: "zoe\u202e@example.com" }] });
		expect(detail).toContain("Identity\nEmail  zoe@example.com");
		const mutation = renderHumanPresentation({ kind: "mutation", title: "User created", receipt: [{ label: "ID", value: "usr_123" }], next: ["Invite the user"] });
		expect(mutation).toContain("ID  usr_123");
	});

	it("renders nested detail data as labeled fields without JSON blobs", () => {
		const detail = renderHumanPresentation({
			kind: "detail",
			title: "User",
			fields: [{
				group: "Details",
				label: "Profile",
				value: {
					name: "Zoe",
					metadata: { plan: "enterprise", regions: ["us", "eu"] },
					memberships: [{ organizationId: "org_1", role: "admin" }],
				},
			}],
		});
		expect(detail).toContain("Profile / Name");
		expect(detail).toContain("Profile / Metadata / Plan");
		expect(detail).toContain("enterprise");
		expect(detail).toContain("us, eu");
		expect(detail).toContain("Profile / Memberships 1 / Organization Id");
		expect(detail).not.toContain('{"');
	});

	it("retains pagination and sibling metadata next to list rows", () => {
		const list = renderHumanPresentation({
			kind: "list",
			title: "Users",
			columns: [{ key: "email", label: "Email" }],
			rows: [{ email: "zoe@example.com" }],
			fields: [
				{ group: "Page", label: "Next cursor", value: "cursor_2" },
				{ group: "Scope", label: "Project ID", value: "proj_1" },
			],
		});
		expect(list).toContain("zoe@example.com");
		expect(list).toContain("Next cursor  cursor_2");
		expect(list).toContain("Project ID  proj_1");
	});
});
