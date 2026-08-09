const test = require("node:test");
const assert = require("node:assert/strict");
const {
  aggregateAvatarCoverage,
  sanitizeAvatarAggregate,
} = require("../src/avatar-aggregate.cjs");

test("avatar coverage exposes only an aggregate partition", () => {
  assert.deepEqual(aggregateAvatarCoverage([
    {hasAvatarUrl: true, hasHeadImageBuffer: false},
    {hasAvatarUrl: false, hasHeadImageBuffer: true},
    {hasAvatarUrl: true, hasHeadImageBuffer: true},
    {hasAvatarUrl: false, hasHeadImageBuffer: false},
  ]), {
    version: 1,
    candidateContactCount: 4,
    avatarUrlCount: 2,
    headImageBufferCount: 2,
    finalAvatarCount: 3,
    missingAvatarCount: 1,
    reasonCounts: {
      urlOnly: 1,
      headImageBufferOnly: 1,
      urlAndHeadImageBuffer: 1,
      noSupportedSource: 1,
    },
  });
});

test("avatar coverage refuses contact details and non-boolean flags", () => {
  assert.throws(() => aggregateAvatarCoverage([{
    hasAvatarUrl: true,
    hasHeadImageBuffer: false,
    identifier: "synthetic-contact",
  }]), /avatar_aggregate_input_invalid/);
  assert.throws(() => aggregateAvatarCoverage([{
    hasAvatarUrl: "https://example.invalid/avatar",
    hasHeadImageBuffer: false,
  }]), /avatar_aggregate_input_invalid/);
});

test("avatar coverage refuses hidden contact details", () => {
  const contact = {
    hasAvatarUrl: true,
    hasHeadImageBuffer: false,
  };
  Object.defineProperty(contact, "identifier", {
    value: "synthetic-contact",
  });
  assert.throws(
    () => aggregateAvatarCoverage([contact]),
    /avatar_aggregate_input_invalid/
  );
});

test("avatar aggregate sanitizer accepts the exact aggregate schema", () => {
  const aggregate = aggregateAvatarCoverage([
    {hasAvatarUrl: true, hasHeadImageBuffer: false},
    {hasAvatarUrl: false, hasHeadImageBuffer: false},
  ]);
  assert.deepEqual(sanitizeAvatarAggregate(aggregate), aggregate);
});

test("avatar aggregate sanitizer rejects schema and reason-key drift", () => {
  const aggregate = aggregateAvatarCoverage([]);
  assert.throws(() => sanitizeAvatarAggregate({
    ...aggregate,
    identifier: "synthetic-contact",
  }), /avatar_aggregate_schema_mismatch/);
  const missing = structuredClone(aggregate);
  delete missing.missingAvatarCount;
  assert.throws(
    () => sanitizeAvatarAggregate(missing),
    /avatar_aggregate_schema_mismatch/
  );
  const unexpectedReason = structuredClone(aggregate);
  unexpectedReason.reasonCounts.networkFailure = 0;
  assert.throws(
    () => sanitizeAvatarAggregate(unexpectedReason),
    /avatar_aggregate_schema_mismatch/
  );
});

test("avatar aggregate sanitizer rejects every forbidden detail class", () => {
  for (const [field, detail] of [
    ["identifier", "synthetic-contact"],
    ["avatarUrl", "https://example.invalid/avatar"],
    ["sourcePath", String.raw`X:\synthetic\avatar.jpg`],
    ["imageData", "data:image/jpeg;base64,AA=="],
    ["decryptKey", "synthetic-key"],
    ["sql", "SELECT synthetic"],
    ["stack", "synthetic stack trace"],
  ]) {
    const extraField = {
      ...aggregateAvatarCoverage([]),
      [field]: detail,
    };
    assert.throws(
      () => sanitizeAvatarAggregate(extraField),
      /avatar_aggregate_schema_mismatch/
    );
    assert.throws(
      () => sanitizeAvatarAggregate({
        ...aggregateAvatarCoverage([]),
        candidateContactCount: detail,
      }),
      /avatar_aggregate_schema_mismatch/
    );
  }
});

test("avatar aggregate sanitizer requires version one and safe counts", () => {
  const aggregate = aggregateAvatarCoverage([]);
  for (const [field, value] of [
    ["candidateContactCount", -1],
    ["avatarUrlCount", 0.5],
    ["headImageBufferCount", 2 ** 53],
    ["finalAvatarCount", true],
    ["missingAvatarCount", null],
  ]) {
    assert.throws(
      () => sanitizeAvatarAggregate({...aggregate, [field]: value}),
      /avatar_aggregate_schema_mismatch/
    );
  }
  assert.throws(
    () => sanitizeAvatarAggregate({...aggregate, version: 2}),
    /avatar_aggregate_schema_mismatch/
  );
  const invalidReason = structuredClone(aggregate);
  invalidReason.reasonCounts.urlOnly = -1;
  assert.throws(
    () => sanitizeAvatarAggregate(invalidReason),
    /avatar_aggregate_schema_mismatch/
  );
});

test("avatar aggregate sanitizer enforces the exact coverage partition", () => {
  const aggregate = aggregateAvatarCoverage([
    {hasAvatarUrl: true, hasHeadImageBuffer: false},
    {hasAvatarUrl: false, hasHeadImageBuffer: true},
    {hasAvatarUrl: true, hasHeadImageBuffer: true},
    {hasAvatarUrl: false, hasHeadImageBuffer: false},
  ]);
  for (const field of [
    "candidateContactCount",
    "avatarUrlCount",
    "headImageBufferCount",
    "finalAvatarCount",
    "missingAvatarCount",
  ]) {
    assert.throws(
      () => sanitizeAvatarAggregate({...aggregate, [field]: 5}),
      /avatar_aggregate_count_mismatch/
    );
  }
  const reasonDrift = structuredClone(aggregate);
  reasonDrift.reasonCounts.urlOnly = 2;
  assert.throws(
    () => sanitizeAvatarAggregate(reasonDrift),
    /avatar_aggregate_count_mismatch/
  );
});

test("avatar aggregate sanitizer rejects hidden sensitive serialization", () => {
  const aggregate = aggregateAvatarCoverage([]);
  Object.defineProperty(aggregate, "toJSON", {
    value: () => ({
      identifier: "synthetic-contact",
      avatarUrl: "https://example.invalid/avatar",
      sourcePath: String.raw`X:\synthetic\avatar.jpg`,
      imageData: "data:image/jpeg;base64,AA==",
      decryptKey: "synthetic-key",
      sql: "SELECT synthetic",
      stack: "synthetic stack",
    }),
  });
  assert.throws(
    () => sanitizeAvatarAggregate(aggregate),
    /avatar_aggregate_schema_mismatch/
  );
});

test("avatar aggregate sanitizer rejects accessor-backed output", () => {
  const aggregate = aggregateAvatarCoverage([]);
  let reads = 0;
  Object.defineProperty(aggregate, "candidateContactCount", {
    configurable: true,
    enumerable: true,
    get() {
      reads += 1;
      return reads < 3 ? 0 : "data:image/jpeg;base64,AA==";
    },
  });
  assert.throws(
    () => sanitizeAvatarAggregate(aggregate),
    /avatar_aggregate_schema_mismatch/
  );
});

test("avatar aggregate sanitizer rejects non-enumerable count fields", () => {
  const aggregate = aggregateAvatarCoverage([]);
  Object.defineProperty(aggregate, "candidateContactCount", {
    configurable: true,
    enumerable: false,
    value: 0,
    writable: true,
  });
  assert.throws(
    () => sanitizeAvatarAggregate(aggregate),
    /avatar_aggregate_schema_mismatch/
  );
});
