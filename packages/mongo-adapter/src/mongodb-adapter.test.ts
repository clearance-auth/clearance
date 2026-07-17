import { ObjectId, UUID } from "mongodb";
import { describe, expect, it, vi } from "vitest";
import { runWithTransaction } from "@clearance/core/context";
import { mongodbAdapter } from "./mongodb-adapter";

type TestIndex = {
	name: string;
	key: Record<string, 1>;
	unique?: boolean | undefined;
	partialFilterExpression?:
		| Record<string, { $type: string }>
		| undefined;
};

class UniqueIndexCollection {
	readonly indexes: TestIndex[] = [
		{ name: "_id_", key: { _id: 1 }, unique: true },
	];
	readonly documents: Record<string, unknown>[] = [];

	listIndexes() {
		return {
			toArray: async () => this.indexes.map((index) => ({ ...index })),
		};
	}

	async createIndex(
		key: Record<string, 1>,
		options: Omit<TestIndex, "key">,
	) {
		this.indexes.push({ key, ...options });
		return options.name;
	}

	async dropIndex(name: string) {
		const index = this.indexes.findIndex((candidate) => candidate.name === name);
		if (index >= 0) this.indexes.splice(index, 1);
	}

	async insertOne(document: Record<string, unknown>) {
		for (const index of this.indexes) {
			if (!index.unique || !this.isIncluded(document, index)) continue;
			const field = Object.keys(index.key)[0]!;
			if (
				this.documents.some(
					(existing) =>
						this.isIncluded(existing, index) &&
						existing[field] === document[field],
				)
			) {
				throw Object.assign(new Error("E11000 duplicate key error"), {
					code: 11000,
				});
			}
		}
		this.documents.push(document);
		return { insertedId: document._id };
	}

	private isIncluded(document: Record<string, unknown>, index: TestIndex) {
		if (!index.partialFilterExpression) return true;
		const [field, condition] = Object.entries(
			index.partialFilterExpression,
		)[0]!;
		if (condition.$type === "string") return typeof document[field] === "string";
		if (condition.$type === "number") return typeof document[field] === "number";
		if (condition.$type === "bool") return typeof document[field] === "boolean";
		if (condition.$type === "date") return document[field] instanceof Date;
		if (condition.$type === "objectId") {
			return document[field] instanceof ObjectId;
		}
		if (condition.$type === "binData") return document[field] instanceof UUID;
		return false;
	}
}

class UniqueIndexDb {
	private readonly collections = new Map<string, UniqueIndexCollection>();

	collection(name: string) {
		let collection = this.collections.get(name);
		if (!collection) {
			collection = new UniqueIndexCollection();
			this.collections.set(name, collection);
		}
		return collection;
	}
}

async function createPasskeyIndexedAdapter() {
	const db = new UniqueIndexDb();
	const options = {
		user: { modelName: "member" },
		plugins: [
			{
				id: "passkey",
				schema: {
					user: {
						fields: {
							passkeyUserHandle: {
								type: "string",
								required: false,
								unique: true,
								fieldName: "webauthn_handle",
							},
						},
					},
					passkey: {
						modelName: "authenticator",
						fields: {
							credentialID: {
								type: "string",
								required: true,
								unique: true,
								fieldName: "credential_key",
							},
						},
					},
					passkeyChallenge: {
						modelName: "ceremonyChallenge",
						fields: {
							digestId: {
								type: "string",
								required: true,
								unique: true,
								fieldName: "challenge_digest",
							},
						},
					},
				},
			},
		],
	} as any;
	const adapter = mongodbAdapter(db as any, {
		transaction: false,
		usePlural: true,
	})(options);
	await (
		adapter as typeof adapter & {
			ensureCredentialAuthorityIndexes(): Promise<void>;
		}
	).ensureCredentialAuthorityIndexes();
	return { adapter, db };
}

function createTransactionAdapter(session: {
	withTransaction: any;
	endSession: () => Promise<void>;
}) {
	const client = {
		startSession: vi.fn(() => session),
	};
	const adapter = mongodbAdapter(
		{ collection: vi.fn() } as any,
		{ client: client as any },
	)({});
	return { adapter, client };
}

describe("mongodb-adapter", () => {
	it("should create mongodb adapter", () => {
		const db = {
			collection: vi.fn(),
		} as any;
		const adapter = mongodbAdapter(db);
		expect(adapter).toBeDefined();
	});

	it("re-runs the complete transaction callback when the driver retries a transient conflict", async () => {
		let attempts = 0;
		const transientConflict = Object.assign(new Error("write conflict"), {
			hasErrorLabel: (label: string) => label === "TransientTransactionError",
		});
		const session = {
			withTransaction: vi.fn(async <T,>(callback: () => Promise<T>) => {
				try {
					return await callback();
				} catch (error) {
					if (
						error === transientConflict &&
						transientConflict.hasErrorLabel("TransientTransactionError")
					) {
						return callback();
					}
					throw error;
				}
			}),
			startTransaction: vi.fn(),
			commitTransaction: vi.fn(async () => {}),
			abortTransaction: vi.fn(async () => {}),
			endSession: vi.fn(async () => {}),
		};
		const { adapter, client } = createTransactionAdapter(session);

		const result = await adapter.transaction(async () => {
			attempts += 1;
			if (attempts === 1) throw transientConflict;
			return { outcome: "team-cap-domain-result" };
		});

		expect(result).toEqual({ outcome: "team-cap-domain-result" });
		expect(attempts).toBe(2);
		expect(session.withTransaction).toHaveBeenCalledTimes(1);
		expect(client.startSession).toHaveBeenCalledTimes(1);
		expect(session.startTransaction).not.toHaveBeenCalled();
		expect(session.commitTransaction).not.toHaveBeenCalled();
		expect(session.abortTransaction).not.toHaveBeenCalled();
		expect(session.endSession).toHaveBeenCalledTimes(1);
	});

	it("does not retry non-transient transaction callback errors", async () => {
		let attempts = 0;
		const applicationError = new Error("organization role is invalid");
		const session = {
			withTransaction: vi.fn(async <T,>(callback: () => Promise<T>) => callback()),
			startTransaction: vi.fn(),
			commitTransaction: vi.fn(async () => {}),
			abortTransaction: vi.fn(async () => {}),
			endSession: vi.fn(async () => {}),
		};
		const { adapter } = createTransactionAdapter(session);

		await expect(
			adapter.transaction(async () => {
				attempts += 1;
				throw applicationError;
			}),
		).rejects.toBe(applicationError);

		expect(attempts).toBe(1);
		expect(session.withTransaction).toHaveBeenCalledTimes(1);
		expect(session.abortTransaction).not.toHaveBeenCalled();
		expect(session.endSession).toHaveBeenCalledTimes(1);
	});

	it("lets the driver retry uncertain commits without re-running the callback", async () => {
		let callbackAttempts = 0;
		let commitAttempts = 0;
		const session = {
			withTransaction: vi.fn(async <T,>(callback: () => Promise<T>) => {
				const result = await callback();
				// MongoDB's driver handles UnknownTransactionCommitResult by retrying
				// commitTransaction internally, without invoking the callback again.
				commitAttempts += 1;
				commitAttempts += 1;
				return result;
			}),
			startTransaction: vi.fn(),
			commitTransaction: vi.fn(async () => {}),
			abortTransaction: vi.fn(async () => {}),
			endSession: vi.fn(async () => {}),
		};
		const { adapter } = createTransactionAdapter(session);

		await expect(
			adapter.transaction(async () => {
				callbackAttempts += 1;
				return "committed";
			}),
		).resolves.toBe("committed");

		expect(callbackAttempts).toBe(1);
		expect(commitAttempts).toBe(2);
		expect(session.commitTransaction).not.toHaveBeenCalled();
		expect(session.endSession).toHaveBeenCalledTimes(1);
	});

	it("keeps nested transaction contexts inside the active driver transaction", async () => {
		const session = {
			withTransaction: vi.fn(async <T,>(callback: () => Promise<T>) => callback()),
			endSession: vi.fn(async () => {}),
		};
		const { adapter, client } = createTransactionAdapter(session);

		await expect(
			runWithTransaction(adapter, () =>
				runWithTransaction(adapter, () => "nested transaction result"),
			),
		).resolves.toBe("nested transaction result");

		expect(session.withTransaction).toHaveBeenCalledTimes(1);
		expect(client.startSession).toHaveBeenCalledTimes(1);
		expect(session.endSession).toHaveBeenCalledTimes(1);
	});

	it("consumeOne returns the deleted document from Mongo metadata", async () => {
		const deleted = {
			_id: "verification-id",
			identifier: "magic-link-token",
		};
		const findOneAndDelete = vi.fn(async () => ({ value: deleted }));
		const db = {
			collection: vi.fn(() => ({
				findOneAndDelete,
			})),
		} as any;
		const adapter = mongodbAdapter(db, { transaction: false })({});

		const result = await adapter.consumeOne({
			model: "verification",
			where: [{ field: "identifier", value: "magic-link-token" }],
		});

		expect(result).toMatchObject({
			id: "verification-id",
			identifier: "magic-link-token",
		});
		expect(findOneAndDelete).toHaveBeenCalledWith(
			{ identifier: "magic-link-token" },
			expect.objectContaining({ includeResultMetadata: true }),
		);
	});

	it("createIfAbsent compares independently transformed ObjectId attempts by value", async () => {
		let stored: Record<string, unknown> | null = null;
		const findOneAndUpdate = vi.fn(
			async (
				_filter: Record<string, unknown>,
				update: { $setOnInsert: Record<string, unknown> },
			) => {
				if (!stored) stored = { ...update.$setOnInsert };
				return { value: { ...stored } };
			},
		);
		const db = {
			collection: vi.fn(() => ({ findOneAndUpdate })),
		} as any;
		const adapter = mongodbAdapter(db, { transaction: false })({});
		const expiresAt = new Date("2026-07-17T00:00:00.000Z");
		const winner = {
			userId: "507f1f77bcf86cd799439011",
			token: "shared",
			expiresAt,
		};
		const loser = {
			userId: "507f1f77bcf86cd799439012",
			token: "shared",
			expiresAt,
		};

		expect(
			await adapter.createIfAbsent({
				model: "session",
				data: winner,
				uniqueBy: { field: "token", value: winner.token },
				attemptBy: { field: "userId", value: winner.userId },
			}),
		).toMatchObject(winner);
		const beforeLoser = {
			...(stored as unknown as Record<string, unknown>),
		};
		expect(
			await adapter.createIfAbsent({
				model: "session",
				data: loser,
				uniqueBy: { field: "token", value: loser.token },
				attemptBy: { field: "userId", value: loser.userId },
			}),
		).toBeNull();
		expect(stored).toEqual(beforeLoser);
		expect(findOneAndUpdate).toHaveBeenCalledWith(
			{ token: "shared" },
			expect.objectContaining({
				$setOnInsert: expect.objectContaining({
					_id: expect.any(ObjectId),
					token: "shared",
					userId: expect.any(ObjectId),
				}),
			}),
			expect.objectContaining({
				upsert: true,
				returnDocument: "after",
				includeResultMetadata: true,
			}),
		);
	});

	const rateLimitOptions = { rateLimit: { storage: "database" } } as any;

	it("incrementOne applies $inc and $set atomically against the guard filter", async () => {
		const findOneAndUpdate = vi.fn(async () => ({
			value: { _id: "counter-id", count: 4, lastRequest: 1700000000000 },
		}));
		const db = {
			collection: vi.fn(() => ({
				findOneAndUpdate,
			})),
		} as any;
		const adapter = mongodbAdapter(db, { transaction: false })(
			rateLimitOptions,
		);

		const result = await adapter.incrementOne({
			model: "rateLimit",
			where: [{ field: "count", value: 5, operator: "lt" }],
			increment: { count: 1 },
			set: { lastRequest: 1700000000000 },
		});

		expect(result).toMatchObject({
			id: "counter-id",
			count: 4,
			lastRequest: 1700000000000,
		});
		expect(findOneAndUpdate).toHaveBeenCalledWith(
			{ count: { $lt: 5 } },
			{ $inc: { count: 1 }, $set: { lastRequest: 1700000000000 } },
			expect.objectContaining({
				returnDocument: "after",
				includeResultMetadata: true,
			}),
		);
	});

	it("incrementOne omits $set when no absolute assignments are provided", async () => {
		const findOneAndUpdate = vi.fn(async () => ({
			value: { _id: "counter-id", count: 11 },
		}));
		const db = {
			collection: vi.fn(() => ({
				findOneAndUpdate,
			})),
		} as any;
		const adapter = mongodbAdapter(db, { transaction: false })(
			rateLimitOptions,
		);

		await adapter.incrementOne({
			model: "rateLimit",
			where: [{ field: "key", value: "a" }],
			increment: { count: 1 },
		});

		expect(findOneAndUpdate).toHaveBeenCalledWith(
			{ key: "a" },
			{ $inc: { count: 1 } },
			expect.anything(),
		);
		const updateArg = (findOneAndUpdate.mock.calls[0] as any[])[1];
		expect(updateArg).not.toHaveProperty("$set");
	});

	it("incrementOne omits $inc for a set-only guarded transition", async () => {
		const findOneAndUpdate = vi.fn(async () => ({
			value: { _id: "counter-id", lastRequest: 1700000000000 },
		}));
		const db = {
			collection: vi.fn(() => ({
				findOneAndUpdate,
			})),
		} as any;
		const adapter = mongodbAdapter(db, { transaction: false })(
			rateLimitOptions,
		);

		await adapter.incrementOne({
			model: "rateLimit",
			where: [{ field: "key", value: "a" }],
			increment: {},
			set: { lastRequest: 1700000000000 },
		});

		expect(findOneAndUpdate).toHaveBeenCalledWith(
			{ key: "a" },
			{ $set: { lastRequest: 1700000000000 } },
			expect.anything(),
		);
		const updateArg = (findOneAndUpdate.mock.calls[0] as any[])[1];
		expect(updateArg).not.toHaveProperty("$inc");
	});

	it("incrementOne returns null when the guard matches no document", async () => {
		const findOneAndUpdate = vi.fn(async () => ({ value: null }));
		const db = {
			collection: vi.fn(() => ({
				findOneAndUpdate,
			})),
		} as any;
		const adapter = mongodbAdapter(db, { transaction: false })(
			rateLimitOptions,
		);

		const result = await adapter.incrementOne({
			model: "rateLimit",
			where: [{ field: "count", value: 5, operator: "lt" }],
			increment: { count: 1 },
		});

		expect(result).toBeNull();
	});

	it("sorts logical ids by MongoDB _id for restartable cursors", async () => {
		const aggregate = vi.fn((_pipeline: unknown[]) => ({
			toArray: vi.fn(async () => []),
		}));
		const db = {
			collection: vi.fn(() => ({ aggregate })),
		} as any;
		const adapter = mongodbAdapter(db, { transaction: false })({});

		await adapter.findMany({
			model: "session",
			sortBy: { field: "id", direction: "asc" },
		});

		expect(aggregate.mock.calls[0]?.[0]).toContainEqual({
			$sort: { _id: 1 },
		});
	});
});

describe("passkey authority indexes", () => {
	it("installs exact remapped indexes without making other user fields unique", async () => {
		const { db } = await createPasskeyIndexedAdapter();

		expect(db.collection("authenticators").indexes).toContainEqual({
			name: "clearance_passkey_credentialID_unique_v1",
			key: { credential_key: 1 },
			unique: true,
		});
		expect(db.collection("ceremonyChallenges").indexes).toContainEqual({
			name: "clearance_passkeyChallenge_digestId_unique_v1",
			key: { challenge_digest: 1 },
			unique: true,
		});
		expect(db.collection("members").indexes).toContainEqual({
			name: "clearance_user_passkeyUserHandle_unique_v1",
			key: { webauthn_handle: 1 },
			unique: true,
			partialFilterExpression: {
				webauthn_handle: { $type: "string" },
			},
		});
		expect(
			db
				.collection("members")
				.indexes.filter((index) => index.name !== "_id_")
				.map((index) => index.key),
		).toEqual([{ webauthn_handle: 1 }]);
		expect(db.collection("sessionCredentials").indexes).toContainEqual(
			expect.objectContaining({
				name: "clearance_sessionCredential_selector_unique_v1",
				unique: true,
			}),
		);
	});

	it("rejects duplicate passkey credential IDs", async () => {
		const { adapter } = await createPasskeyIndexedAdapter();
		await adapter.create({
			model: "passkey",
			data: { credentialID: "credential-1" },
		});

		await expect(
			adapter.create({
				model: "passkey",
				data: { credentialID: "credential-1" },
			}),
		).rejects.toMatchObject({ code: 11000 });
	});

	it("rejects duplicate passkey challenge digests", async () => {
		const { adapter } = await createPasskeyIndexedAdapter();
		await adapter.create({
			model: "passkeyChallenge",
			data: { digestId: "digest-1" },
		});

		await expect(
			adapter.create({
				model: "passkeyChallenge",
				data: { digestId: "digest-1" },
			}),
		).rejects.toMatchObject({ code: 11000 });
	});

	it("allows absent and null user handles but rejects duplicate real handles", async () => {
		const { adapter } = await createPasskeyIndexedAdapter();
		const user = {
			name: "Passkey user",
			email: "shared@example.test",
			emailVerified: true,
			createdAt: new Date(),
			updatedAt: new Date(),
		};

		await adapter.create({ model: "user", data: user });
		await adapter.create({ model: "user", data: { ...user } });
		await adapter.create({
			model: "user",
			data: { ...user, passkeyUserHandle: null },
		});
		await adapter.create({
			model: "user",
			data: { ...user, passkeyUserHandle: "handle-1" },
		});

		await expect(
			adapter.create({
				model: "user",
				data: { ...user, passkeyUserHandle: "handle-1" },
			}),
		).rejects.toMatchObject({ code: 11000 });
	});
});

describe("uuid support", () => {
	const uuidRegex =
		/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
	const uuid = "550e8400-e29b-41d4-a716-446655440000";

	function createMockDb() {
		const insertedDocs: any[] = [];
		const updatedFilters: any[] = [];
		const updatedValues: any[] = [];

		const collection = vi.fn(() => ({
			insertOne: vi.fn(async (doc: any) => {
				insertedDocs.push(doc);
				return { insertedId: doc._id };
			}),
			aggregate: vi.fn(() => ({
				toArray: vi.fn(async () => {
					return [];
				}),
			})),
			findOneAndUpdate: vi.fn(async (filter: any, update: any) => {
				updatedFilters.push(filter);
				updatedValues.push(update);
				return { value: { ...update.$set, _id: filter._id } };
			}),
			deleteOne: vi.fn(async () => {}),
		}));

		return {
			db: { collection } as any,
			insertedDocs,
			updatedFilters,
			updatedValues,
		};
	}

	function createAdapter(
		db: any,
		generateId: "uuid" | (() => string) | undefined,
	) {
		const adapterFactory = mongodbAdapter(db, { transaction: false });
		return adapterFactory({
			database: {} as any,
			advanced: {
				database: {
					...(generateId !== undefined ? { generateId } : {}),
				},
			},
		} as any);
	}

	it("should store _id as BSON UUID when generateId is 'uuid'", async () => {
		const { db, insertedDocs } = createMockDb();
		const adapter = createAdapter(db, "uuid");

		await adapter.create({
			model: "user",
			data: {
				name: "Test",
				email: "test@test.com",
				emailVerified: true,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});

		expect(insertedDocs.length).toBe(1);
		expect(insertedDocs[0]._id).toBeInstanceOf(UUID);
		expect(insertedDocs[0]._id.toString()).toMatch(uuidRegex);
	});

	it("should store FK fields as BSON UUID when generateId is 'uuid'", async () => {
		const { db, insertedDocs } = createMockDb();
		const adapter = createAdapter(db, "uuid");

		await adapter.create({
			model: "session",
			data: {
				userId: uuid,
				token: "test-token",
				expiresAt: new Date(),
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});

		expect(insertedDocs.length).toBe(1);
		expect(insertedDocs[0]._id).toBeInstanceOf(UUID);
		expect(insertedDocs[0].userId).toBeInstanceOf(UUID);
		expect(insertedDocs[0].userId.toString()).toBe(uuid);
	});

	it("should store _id as ObjectId when generateId is not set", async () => {
		const { db, insertedDocs } = createMockDb();
		const adapter = createAdapter(db, undefined);

		await adapter.create({
			model: "user",
			data: {
				name: "Test",
				email: "test@test.com",
				emailVerified: true,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});

		expect(insertedDocs.length).toBe(1);
		expect(insertedDocs[0]._id).toBeInstanceOf(ObjectId);
	});

	it("should convert BSON UUID to string in output", async () => {
		const bsonUuid = new UUID(uuid);
		const { db } = createMockDb();

		// Override aggregate to return a document with BSON UUID
		(db.collection as any).mockReturnValue({
			aggregate: vi.fn(() => ({
				toArray: vi.fn(async () => [
					{
						_id: bsonUuid,
						name: "Test",
						email: "test@test.com",
					},
				]),
			})),
		});

		const adapter = createAdapter(db, "uuid");
		const result = await adapter.findOne({
			model: "user",
			where: [{ field: "id", value: uuid }],
		});

		expect(result).not.toBeNull();
		expect((result as Record<string, unknown>).id).toBe(uuid);
	});
});
