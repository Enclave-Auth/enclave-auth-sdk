/**
 * Types for importing users from a legacy identity provider into Enclave Auth.
 * Persistence lives in enclave-auth-api — this SDK only shapes the contract.
 */

export interface ImportedUser {
  externalId: string;
  email: string;
  displayName?: string;
  metadata?: Record<string, unknown>;
}

export interface MigrationSource {
  name: string;
  listUsers(): AsyncIterable<ImportedUser>;
  verifyLegacyCredential?(
    externalId: string,
    credential: unknown,
  ): Promise<boolean>;
}

export type MigrationRecordStatus = "pending_claim" | "claimed" | "expired";
