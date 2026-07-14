/**
 * Migration import orchestrator — thin passthrough today.
 *
 * Centralizing the call site allows future retry / backoff / dedup without
 * changing enclave-auth-api or adapters. No database or network I/O here.
 */

import type { ImportedUser, MigrationSource } from "./types.js";

/**
 * Yield users from a migration source.
 */
export async function* runImport(
  source: MigrationSource,
): AsyncIterable<ImportedUser> {
  if (!source?.name) {
    throw new Error("MigrationSource.name is required");
  }
  if (typeof source.listUsers !== "function") {
    throw new Error("MigrationSource.listUsers is required");
  }
  for await (const user of source.listUsers()) {
    if (!user?.externalId || !user.email) {
      throw new Error(
        "ImportedUser requires non-empty externalId and email",
      );
    }
    yield user;
  }
}

export type {
  ImportedUser,
  MigrationRecordStatus,
  MigrationSource,
} from "./types.js";
