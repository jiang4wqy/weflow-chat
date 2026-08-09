const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {deriveAreaLayout} = require("./path-policy.cjs");
const {
  runAvatarAggregateGateway,
  runMediaOpenabilityGateway,
  runSnapshotGateway,
} = require("./worker-gateway.cjs");
const {sanitizeResult} = require("./sanitize-result.cjs");

const SNAPSHOTS_ROOT_ENV = "WEFLOW_CHAT_SNAPSHOTS_ROOT";
const DATA_OPERATIONS = new Set([
  "avatar-aggregate", "media-openability", "validate-snapshot"
]);
const OPERATIONS = new Set([
  "smoke", "safe-envelope-roundtrip", ...DATA_OPERATIONS
]);
const DIAGNOSTIC_STAGES = new Set([
  "avatar_gateway_started", "contacts_loaded", "avatar_urls_loaded",
  "head_image_buffers_loaded", "avatar_aggregate_ready",
  "media_gateway_started", "media_index_started", "media_index_ready",
  "media_stream_started", "media_stream_page_loaded", "media_probe_ready",
  "media_candidate_identity_ready", "media_candidate_unique",
  "media_image_inspect_started", "media_image_inspect_ready",
  "media_video_inspect_started", "media_video_inspect_ready",
  "media_candidate_counted",
  "media_image_md5_ready", "media_image_hardlink_started",
  "media_image_hardlink_ready", "media_image_hardlink_validated",
  "media_image_hardlink_success", "media_image_hardlink_data_ready",
  "media_image_hardlink_filename_ready",
  "media_image_hardlink_fullpath_ready",
  "media_image_hardlink_basename_matched",
  "media_image_token_ready", "media_image_index_lookup_ready",
  "media_image_unavailable", "media_image_candidate_selected",
  "media_image_prefix_read", "media_image_prefix_decoded",
  "gateway_started", "paths_set", "connection_tested", "account_opened",
  "sessions_loaded", "aggregate_loaded", "message_stats_loaded",
  "message_list_started", "message_list_loaded",
  "message_list_validated", "media_list_started", "media_list_loaded",
  "media_list_validated",
  "message_entry_path_rejected", "message_list_conflict",
  "message_kind_conflict", "media_entry_path_rejected",
  "media_list_conflict", "media_kind_conflict",
  "database_lists_loaded", "database_files_discovered",
  "database_unclassified", "database_scanned", "fingerprints_ready",
  "tables_list_started", "tables_list_loaded",
  "table_schema_started", "table_schema_loaded",
  "table_schema_failed", "table_schema_empty"
]);
const EMPTY_GATES = () => ({userDataIsolated: false, documentsIsolated: false,
  singleInstanceLockAcquired: false, safeStorageAvailable: false,
  syntheticEnvelopeRoundtrip: false, nativeProtectionAuthenticated: false,
  workerSetPathsCalled: false});
const exact = (value, keys) => value && typeof value === "object" &&
  !Array.isArray(value) && Object.keys(value).length === keys.length &&
  keys.every(key => Object.hasOwn(value, key));
const canonicalUuid = value => {
  if (typeof value !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) {
    throw new Error("request_run_id_invalid");
  }
  return value;
};
const assertOrdinaryAbsoluteChain = (target, {requireTarget = true} = {}) => {
  if (typeof target !== "string" || !path.isAbsolute(target)) {
    throw new Error("request_path_rejected");
  }
  const absolute = path.resolve(target);
  const parsed = path.parse(absolute);
  let cursor = parsed.root;
  for (const component of absolute.slice(parsed.root.length)
         .split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    let info;
    try {
      info = fs.lstatSync(cursor);
    } catch (error) {
      if (error && error.code === "ENOENT") continue;
      throw error;
    }
    if (info.isSymbolicLink()) {
      throw new Error("request_reparse_rejected");
    }
  }
  if (!requireTarget) return absolute;
  return fs.realpathSync.native(absolute);
};
const pathKey = value => path.normalize(value).toLowerCase();
const samePath = (left, right) => pathKey(left) === pathKey(right);
const electronPathGates = ({app, boot}) => {
  try {
    return {
      userDataIsolated:
        samePath(assertOrdinaryAbsoluteChain(app.getPath("userData")),
                 assertOrdinaryAbsoluteChain(boot.userDataDir)),
      documentsIsolated:
        samePath(assertOrdinaryAbsoluteChain(app.getPath("documents")),
                 assertOrdinaryAbsoluteChain(boot.documentsDir))
    };
  } catch {
    return {userDataIsolated: false, documentsIsolated: false};
  }
};
exports._electronPathsMatchForTest = args =>
  Object.values(electronPathGates(args)).every(Boolean);
const atomicWriteSanitized = (target, value, sanitizer, {
  beforeCommit = () => {}, chainCheck = assertOrdinaryAbsoluteChain,
} = {}) => {
  const safe = sanitizer(value);
  const encoded = Buffer.from(JSON.stringify(safe), "utf8");
  chainCheck(path.dirname(target));
  chainCheck(target, {requireTarget: false});
  const temporary = `${target}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const sameFile = (left, right) =>
    left.dev === right.dev && left.ino === right.ino &&
    left.size === right.size;
  const readDescriptor = descriptor => {
    const bytes = Buffer.alloc(encoded.length);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(
        descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    if (offset !== bytes.length || !bytes.equals(encoded)) {
      throw new Error("result_temporary_changed");
    }
  };
  let descriptor;
  try {
    chainCheck(temporary, {requireTarget: false});
    descriptor = fs.openSync(temporary, "wx+");
    let offset = 0;
    while (offset < encoded.length) {
      offset += fs.writeSync(
        descriptor, encoded, offset, encoded.length - offset, offset);
    }
    fs.fsyncSync(descriptor);
    chainCheck(temporary);
    const held = fs.fstatSync(descriptor, {bigint: true});
    const named = fs.lstatSync(temporary, {bigint: true});
    if (!held.isFile() || !named.isFile() ||
        held.size !== BigInt(encoded.length) || !sameFile(held, named)) {
      throw new Error("result_temporary_changed");
    }
    beforeCommit();
    chainCheck(path.dirname(target));
    chainCheck(target, {requireTarget: false});
    chainCheck(temporary);
    const beforeLink = fs.fstatSync(descriptor, {bigint: true});
    if (!beforeLink.isFile() || beforeLink.size !== BigInt(encoded.length)) {
      throw new Error("result_temporary_changed");
    }
    readDescriptor(descriptor);
    fs.linkSync(temporary, target);
    const published = fs.lstatSync(target, {bigint: true});
    let publishedBytes;
    try {
      publishedBytes = fs.readFileSync(target);
    } catch {
      publishedBytes = null;
    }
    if (!published.isFile() || !sameFile(beforeLink, published) ||
        publishedBytes === null || !publishedBytes.equals(encoded)) {
      const source = fs.lstatSync(temporary, {bigint: true});
      const current = fs.lstatSync(target, {bigint: true});
      if (!sameFile(source, current)) {
        throw new Error("result_publish_cleanup_failed");
      }
      fs.rmSync(target);
      throw new Error("result_temporary_changed");
    }
  } finally {
    try {
      fs.rmSync(temporary, {force: true});
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
  }
};
const atomicWrite = (target, value, options) =>
  atomicWriteSanitized(target, value, sanitizeResult, options);
exports._atomicWriteForTest = options => atomicWrite(
  options.target, options.value, options);
const baseResult = boot => ({version: 1, runId: boot.request.runId,
  operation: boot.request.operation, status: "compatibility_blocked",
  reasonCode: "validator_unhandled", gates: EMPTY_GATES(), validation: null,
  callsBeforeOpen: []});

function prepareBoot({app, argv, env, resourcesPath}, snapshotsRoot) {
  const indices = argv.flatMap((item, index) =>
    item === "--weflow-validator-request" ? [index] : []);
  if (indices.length === 0) return {enabled: false};
  if (indices.length !== 1 || indices[0] + 1 >= argv.length) {
    throw new Error("request_argument_rejected");
  }
  const requestPath = assertOrdinaryAbsoluteChain(argv[indices[0] + 1]);
  if (path.basename(requestPath) !== "request.json" ||
      path.basename(path.dirname(requestPath)) !== "request") {
    throw new Error("request_path_rejected");
  }
  const attemptRoot = path.dirname(path.dirname(requestPath));
  canonicalUuid(path.basename(attemptRoot));
  const areaRoot = path.dirname(attemptRoot);
  const area = path.basename(areaRoot);
  const validatorRoot = path.dirname(areaRoot);
  const runRoot = path.dirname(validatorRoot);
  if (typeof snapshotsRoot !== "string" || !path.isAbsolute(snapshotsRoot)) {
    throw new Error("request_snapshots_root_rejected");
  }
  const fixedSnapshotsRoot = assertOrdinaryAbsoluteChain(snapshotsRoot);
  if (!samePath(fixedSnapshotsRoot, path.resolve(snapshotsRoot))) {
    throw new Error("request_snapshots_root_rejected");
  }
  if (!samePath(path.dirname(runRoot), fixedSnapshotsRoot)) {
    throw new Error("request_snapshots_root_rejected");
  }
  if (typeof resourcesPath !== "string" ||
      !path.isAbsolute(resourcesPath)) {
    throw new Error("request_runtime_mismatch");
  }
  const runtimeResources = assertOrdinaryAbsoluteChain(resourcesPath);
  const weFlowRoot = path.dirname(runtimeResources);
  const runtimeRoot = path.dirname(weFlowRoot);
  const runtimeRunRoot = path.dirname(runtimeRoot);
  if (path.basename(runtimeResources) !== "resources" ||
      path.basename(weFlowRoot) !== "WeFlow" ||
      path.basename(runtimeRoot) !== "runtime" ||
      !samePath(runtimeRunRoot, runRoot)) {
    throw new Error("request_runtime_mismatch");
  }
  const request = JSON.parse(fs.readFileSync(requestPath, "utf8"));
  const keys = DATA_OPERATIONS.has(request.operation) ?
    ["operation", "runId", "area"] : ["operation", "runId"];
  if (!exact(request, keys) || !OPERATIONS.has(request.operation) ||
      (DATA_OPERATIONS.has(request.operation) &&
       (!new Set(["validation", "active", "presentation"]).has(request.area) ||
         request.area !== area ||
         (request.operation === "media-openability" &&
          request.area !== "presentation")))) {
    throw new Error("request_schema_mismatch");
  }
  canonicalUuid(request.runId);
  const expectedArea = DATA_OPERATIONS.has(request.operation) ?
    request.area : "validation";
  if (path.basename(validatorRoot) !== "validator" || area !== expectedArea ||
      !path.basename(runRoot).endsWith(`-${request.runId}`)) {
    throw new Error("request_ancestry_rejected");
  }
  const userDataDir = path.join(attemptRoot, "profile");
  const documentsDir = path.join(attemptRoot, "documents");
  const cacheDir = path.join(attemptRoot, "cache");
  const resultPath = path.join(attemptRoot, "result", "result.json");
  for (const directory of [
    userDataDir, documentsDir, cacheDir, path.dirname(resultPath)
  ]) {
    const resolved = assertOrdinaryAbsoluteChain(directory);
    if (!resolved.startsWith(assertOrdinaryAbsoluteChain(attemptRoot) + path.sep)) {
      throw new Error("request_path_rejected");
    }
  }
  app.setPath("userData", userDataDir); app.setPath("documents", documentsDir);
  env.WEFLOW_USER_DATA_PATH = userDataDir;
  env.WEFLOW_CONFIG_CWD = userDataDir;
  return {enabled: true, request, requestPath, attemptRoot, runRoot,
          userDataDir, documentsDir, cacheDir, resultPath,
          runtimeResources};
}
exports.prepareBoot = args => prepareBoot(
  args, args && args.env && args.env[SNAPSHOTS_ROOT_ENV]);
exports._prepareBootForTest = (args, snapshotsRoot) =>
  prepareBoot(args, snapshotsRoot);

exports.writeEarlyFailure = function (boot, reasonCode) {
  if (!boot || !boot.enabled || !boot.resultPath) return;
  const value = baseResult(boot); value.reasonCode = reasonCode;
  atomicWrite(boot.resultPath, value);
};

async function roundtripSupportedEncryptedField({config, configPath, probe}) {
  const field = "decryptKey";
  const original = await config.get(field);
  if (typeof original !== "string" || !/^[0-9a-f]{64}$/i.test(original) ||
      typeof probe !== "string" || !/^[0-9a-f]{64}$/i.test(probe) ||
      probe.toLowerCase() === original.toLowerCase()) {
    throw new Error("safe_envelope_contract");
  }
  let encrypted = false;
  try {
    await config.set(field, probe);
    const reread = await config.get(field);
    const bytes = fs.readFileSync(configPath, "utf8");
    encrypted = reread === probe && !bytes.includes(probe) &&
      bytes.includes("safe:");
  } finally {
    try {
      await config.set(field, original);
    } catch {
      fs.rmSync(configPath, {force: true});
      throw new Error("safe_envelope_roundtrip_failed");
    }
  }
  const restored = await config.get(field);
  const restoredBytes = fs.readFileSync(configPath, "utf8");
  if (!encrypted || restored !== original || restoredBytes.includes(probe)) {
    fs.rmSync(configPath, {force: true});
    throw new Error("safe_envelope_roundtrip_failed");
  }
  return true;
}
exports._roundtripSupportedEncryptedFieldForTest =
  roundtripSupportedEncryptedField;

async function runValidator({boot, ConfigService, wcdbService,
                            resourcesPath, app}, safeStorage) {
  const value = baseResult(boot);
  value.gates.singleInstanceLockAcquired = true;
  Object.assign(value.gates, electronPathGates({app, boot}));
  if (!value.gates.userDataIsolated ||
      !value.gates.documentsIsolated) {
    value.reasonCode = "electron_path_mismatch";
    atomicWrite(boot.resultPath, value);
    return 70;
  }
  value.gates.safeStorageAvailable = safeStorage.isEncryptionAvailable();
  if (!value.gates.safeStorageAvailable) {
    value.reasonCode = "safe_storage_unavailable";
  } else if (boot.request.operation === "smoke") {
    value.status = "ok"; value.reasonCode = null;
  } else if (boot.request.operation === "safe-envelope-roundtrip") {
    const config = new ConfigService();
    try {
      await roundtripSupportedEncryptedField({
        config,
        configPath: path.join(boot.userDataDir, "WeFlow-config.json"),
        probe: crypto.randomBytes(32).toString("hex").toUpperCase()
      });
    } catch {
      value.reasonCode = "safe_envelope_roundtrip_failed";
    }
    if (value.reasonCode !== "safe_envelope_roundtrip_failed") {
      value.gates.syntheticEnvelopeRoundtrip = true;
      value.status = "ok"; value.reasonCode = null;
    }
  } else {
    const expectedResources = assertOrdinaryAbsoluteChain(
      path.join(boot.runtimeResources, "resources"));
    if (!samePath(assertOrdinaryAbsoluteChain(resourcesPath),
                  expectedResources)) {
      value.reasonCode = "worker_contract_mismatch";
      atomicWrite(boot.resultPath, value);
      return 70;
    }
    const config = new ConfigService();
    const dbPath = await config.get("dbPath");
    const sourceAccountName = await config.get("myWxid");
    const topKey = await config.get("decryptKey");
    const allAccounts = await config.get("wxidConfigs");
    const nestedKey = allAccounts && allAccounts[sourceAccountName] &&
      allAccounts[sourceAccountName].decryptKey;
    if (![topKey, nestedKey].every(item => typeof item === "string" &&
          /^[0-9a-f]{64}$/i.test(item)) || topKey.toLowerCase() !== nestedKey.toLowerCase()) {
      value.reasonCode = "safe_envelope_contract";
    } else {
      const areaLayout = deriveAreaLayout({runRoot: boot.runRoot,
        area: boot.request.area, sourceAccountName});
      if (fs.realpathSync.native(path.resolve(dbPath)) !==
          fs.realpathSync.native(areaLayout.roleRoot)) {
        throw new Error("config_db_path_mismatch");
      }
      const stagePath = path.join(
        boot.userDataDir, "validator-stage.log");
      fs.writeFileSync(stagePath, "", {flag: "wx"});
      const gatewayRunner = {
        "avatar-aggregate": runAvatarAggregateGateway,
        "media-openability": runMediaOpenabilityGateway,
        "validate-snapshot": runSnapshotGateway
      }[boot.request.operation];
      const gatewayRequest = {
        resourcesPath, userDataDir: boot.userDataDir,
        dbStorageDir: areaLayout.dbStorage,
        sourceAccountName, syntheticHexKey: topKey.toUpperCase(),
        markStage(stage) {
          if (!DIAGNOSTIC_STAGES.has(stage)) {
            throw new Error("worker_contract_mismatch");
          }
          fs.appendFileSync(stagePath, `${stage}\n`, "utf8");
        }};
      if (boot.request.operation === "media-openability") {
        gatewayRequest.imageXorKey = await config.get("imageXorKey");
        gatewayRequest.imageAesKey = await config.get("imageAesKey");
      }
      const gateway = await gatewayRunner(wcdbService, gatewayRequest);
      value.status = gateway.status; value.reasonCode = gateway.reasonCode;
      value.validation = gateway.status !== "ok" ? null : {
        "avatar-aggregate": gateway.avatarAggregate,
        "media-openability": gateway.mediaOpenability,
        "validate-snapshot": gateway.validation
      }[boot.request.operation];
      value.callsBeforeOpen = gateway.callsBeforeOpen;
      value.gates.nativeProtectionAuthenticated = gateway.nativeProtectionAuthenticated;
      value.gates.workerSetPathsCalled = gateway.workerSetPathsCalled;
    }
  }
  atomicWrite(boot.resultPath, value);
  return value.status === "ok" ? 0 : 70;
}
exports.runValidator = args =>
  runValidator(args, require("electron").safeStorage);
exports._runValidatorForTest = (args, {safeStorage}) =>
  runValidator(args, safeStorage);
