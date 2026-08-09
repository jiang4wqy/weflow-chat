const test = require("node:test");
const assert = require("node:assert/strict");
const {aggregateValidation} = require("../src/aggregate.cjs");
const {sanitizeResult} = require("../src/sanitize-result.cjs");
const {
  coverageFixture,
  validValidationResult
} = require("./helpers.cjs");

test("sanitizer rejects a secret-bearing result", () => {
  assert.throws(() => sanitizeResult({
    status: "ok",
    decryptKey: "safe:ZmFrZQ=="
  }), /result_sensitive_field/);
});

test("sanitizer allows only the three named SHA-256 fields", () => {
  const result = validValidationResult();
  assert.deepEqual(sanitizeResult(result), result);
  assert.throws(() => sanitizeResult({
    ...result,
    unexpectedDigest: "D".repeat(64)
  }), /result_sensitive_value/);
  const lowercase = structuredClone(result);
  lowercase.validation.schemaFingerprint = "d".repeat(64);
  assert.throws(
    () => sanitizeResult(lowercase),
    /result_invalid_fingerprint/
  );
});

test("media sanitizer enforces exact safe partitioned counts", () => {
  const result = validValidationResult();
  result.operation = "media-openability";
  result.validation = {
    version: 1,
    candidateCount: 3,
    imageCandidateCount: 2,
    videoCandidateCount: 1,
    locallyUnavailableCount: 1,
    localFileCount: 2,
    readableImageCount: 1,
    readableVideoCount: 1,
    unreadableLocalCount: 0
  };
  assert.deepEqual(sanitizeResult(result), result);
  for (const validation of [
    {...result.validation, candidateCount: 4},
    {...result.validation, candidateCount: 2 ** 53},
    {...result.validation, candidateCount: true},
    {...result.validation, path: String.raw`X:\forbidden\media.dat`}
  ]) {
    assert.throws(
      () => sanitizeResult({...result, validation}),
      /result_schema_mismatch|result_sensitive_field/
    );
  }
});

test("database coverage detects a missing zero-row database", () => {
  const {complete, missing} = coverageFixture();
  const all = aggregateValidation(complete);
  const partial = aggregateValidation(missing);
  assert.equal(all.aggregateFingerprint, partial.aggregateFingerprint);
  assert.equal(all.schemaFingerprint, partial.schemaFingerprint);
  assert.notEqual(
    all.databaseCoverageFingerprint,
    partial.databaseCoverageFingerprint
  );
});

test("migrate databases remain in read-only coverage", () => {
  const input = {
    sourceAccountName: "synthetic",
    nativeTotal: 0,
    databases: [{
      relativePath: "migrate/migrate.db",
      kind: "migrate",
      tables: []
    }]
  };

  const withMigrate = aggregateValidation(input);
  const withoutMigrate = aggregateValidation({...input, databases: []});

  assert.equal(withMigrate.databaseCount, 1);
  assert.notEqual(
    withMigrate.databaseCoverageFingerprint,
    withoutMigrate.databaseCoverageFingerprint
  );
});
