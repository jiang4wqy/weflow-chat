// validator-node/src/sanitize-result.cjs
const {
  sanitizeAvatarAggregate,
} = require("./avatar-aggregate.cjs");

const FINGERPRINTS = new Set([
  "schemaFingerprint", "aggregateFingerprint",
  "databaseCoverageFingerprint"
]);
const RESULT_KEYS = new Set([
  "version", "runId", "operation", "status", "reasonCode",
  "gates", "validation", "callsBeforeOpen"
]);
const GATE_KEYS = new Set([
  "userDataIsolated", "documentsIsolated", "singleInstanceLockAcquired",
  "safeStorageAvailable", "syntheticEnvelopeRoundtrip",
  "nativeProtectionAuthenticated", "workerSetPathsCalled"
]);
const VALIDATION_KEYS = new Set([
  "databaseCount", "tableCount", "recordCount", "minTimestamp",
  "maxTimestamp", ...FINGERPRINTS
]);
const MEDIA_OPENABILITY_KEYS = new Set([
  "version", "candidateCount", "imageCandidateCount", "videoCandidateCount",
  "locallyUnavailableCount", "localFileCount", "readableImageCount",
  "readableVideoCount", "unreadableLocalCount"
]);
const exact = (value, keys) => value && typeof value === "object" &&
  !Array.isArray(value) && Object.keys(value).length === keys.size &&
  Object.keys(value).every(key => keys.has(key));

exports.sanitizeResult = function (value) {
  const inspect = (item, field = "") => {
    if (typeof item === "string" && /^[0-9A-Fa-f]{64}$/.test(item) &&
        !FINGERPRINTS.has(field)) {
      throw new Error("result_sensitive_value");
    }
    if (Array.isArray(item)) item.forEach(child => inspect(child));
    else if (item && typeof item === "object") {
      for (const [key, child] of Object.entries(item)) inspect(child, key);
    }
  };
  inspect(value);
  const encoded = JSON.stringify(value);
  if (/decryptKey|imageAesKey|imageXorKey|username|content|stack|safe:|lock:|wxid_/i.test(encoded) ||
      /[A-Za-z]:\\|\\\\/.test(encoded)) {
    throw new Error("result_sensitive_field");
  }
  if (!exact(value, RESULT_KEYS) || !exact(value.gates, GATE_KEYS) ||
      !Object.values(value.gates).every(item => typeof item === "boolean") ||
      !Array.isArray(value.callsBeforeOpen)) {
    throw new Error("result_schema_mismatch");
  }
  const operations = new Set(["avatar-aggregate", "media-openability", "smoke",
                              "safe-envelope-roundtrip",
                              "validate-snapshot"]);
  const statuses = new Set(["ok", "compatibility_blocked"]);
  const reasons = new Set([null, "validator_unhandled",
    "single_instance_lock_denied", "safe_storage_unavailable",
    "electron_path_mismatch",
    "safe_envelope_roundtrip_failed", "safe_envelope_contract",
    "connection_failed", "open_failed", "sessions_failed",
    "aggregate_failed", "media_probe_failed", "worker_contract_mismatch"]);
  if (value.version !== 1 || !operations.has(value.operation) ||
      !statuses.has(value.status) ||
      !reasons.has(value.reasonCode) ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.runId) ||
      ((value.status === "ok") !== (value.reasonCode === null)) ||
      ![[], ["setPaths"], ["setPaths", "testConnection"]]
        .some(item => JSON.stringify(item) === JSON.stringify(value.callsBeforeOpen))) {
    throw new Error("result_schema_mismatch");
  }
  const okGates = {
    smoke: {userDataIsolated: true, documentsIsolated: true,
      singleInstanceLockAcquired: true, safeStorageAvailable: true,
      syntheticEnvelopeRoundtrip: false,
      nativeProtectionAuthenticated: false, workerSetPathsCalled: false},
    "safe-envelope-roundtrip": {userDataIsolated: true,
      documentsIsolated: true, singleInstanceLockAcquired: true,
      safeStorageAvailable: true, syntheticEnvelopeRoundtrip: true,
      nativeProtectionAuthenticated: false, workerSetPathsCalled: false},
    "validate-snapshot": {userDataIsolated: true,
      documentsIsolated: true, singleInstanceLockAcquired: true,
      safeStorageAvailable: true, syntheticEnvelopeRoundtrip: false,
      nativeProtectionAuthenticated: true, workerSetPathsCalled: true},
    "avatar-aggregate": {userDataIsolated: true,
      documentsIsolated: true, singleInstanceLockAcquired: true,
      safeStorageAvailable: true, syntheticEnvelopeRoundtrip: false,
      nativeProtectionAuthenticated: true, workerSetPathsCalled: true},
    "media-openability": {userDataIsolated: true,
      documentsIsolated: true, singleInstanceLockAcquired: true,
      safeStorageAvailable: true, syntheticEnvelopeRoundtrip: false,
      nativeProtectionAuthenticated: true, workerSetPathsCalled: true}
  };
  if (value.status === "ok") {
    const expectedCalls = new Set([
      "avatar-aggregate", "media-openability", "validate-snapshot"
    ]).has(value.operation) ?
      ["setPaths", "testConnection"] : [];
    if (!Object.entries(okGates[value.operation]).every(
          ([name, expected]) => value.gates[name] === expected) ||
        JSON.stringify(value.callsBeforeOpen) !==
          JSON.stringify(expectedCalls)) {
      throw new Error("result_gate_mismatch");
    }
  } else if (value.gates.nativeProtectionAuthenticated ||
             value.validation !== null ||
             value.gates.workerSetPathsCalled !==
               value.callsBeforeOpen.includes("setPaths")) {
    throw new Error("result_gate_mismatch");
  }
  if (value.operation === "avatar-aggregate" && value.status === "ok") {
    sanitizeAvatarAggregate(value.validation);
  } else if (value.operation === "media-openability" &&
             value.status === "ok") {
    if (!exact(value.validation, MEDIA_OPENABILITY_KEYS) ||
        ![...MEDIA_OPENABILITY_KEYS].every(name =>
          Number.isSafeInteger(value.validation[name]) &&
          value.validation[name] >= 0) ||
        value.validation.version !== 1 ||
        value.validation.candidateCount !==
          value.validation.imageCandidateCount +
          value.validation.videoCandidateCount ||
        value.validation.candidateCount !==
          value.validation.locallyUnavailableCount +
          value.validation.localFileCount ||
        value.validation.localFileCount !==
          value.validation.readableImageCount +
          value.validation.readableVideoCount +
          value.validation.unreadableLocalCount) {
      throw new Error("result_schema_mismatch");
    }
  } else if (value.operation === "validate-snapshot" &&
             value.status === "ok") {
    if (!exact(value.validation, VALIDATION_KEYS)) {
      throw new Error("result_schema_mismatch");
    }
    for (const name of ["databaseCount", "tableCount", "recordCount"]) {
      if (!Number.isSafeInteger(value.validation[name]) ||
          value.validation[name] < 0) throw new Error("result_schema_mismatch");
    }
    for (const name of ["minTimestamp", "maxTimestamp"]) {
      if (value.validation[name] !== null &&
          !Number.isSafeInteger(value.validation[name])) {
        throw new Error("result_schema_mismatch");
      }
    }
    for (const name of FINGERPRINTS) {
      if (!/^[0-9A-F]{64}$/.test(value.validation[name])) {
        throw new Error("result_invalid_fingerprint");
      }
    }
  } else if (value.validation !== null) {
    throw new Error("result_schema_mismatch");
  }
  const scrubbed = JSON.parse(encoded);
  return scrubbed;
};
