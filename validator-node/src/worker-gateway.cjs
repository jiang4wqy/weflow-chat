const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {aggregateValidation} = require("./aggregate.cjs");
const {
  aggregateAvatarCoverage,
  sanitizeAvatarAggregate,
} = require("./avatar-aggregate.cjs");

const ALLOWED = new Set([
  "setPaths", "testConnection", "open", "getSessions",
  "listMessageDbs", "listMediaDbs", "listTables", "getTableSchema",
  "getMessageTableStats", "getMessageTableTimeRange", "getAggregateStats",
  "getContactsCompact", "getAvatarUrls", "getHeadImageBuffers",
  "getMediaStream", "resolveImageHardlink", "resolveVideoHardlinkMd5"
]);
const digest = value => crypto.createHash("sha256")
  .update(JSON.stringify(value)).digest("hex").toUpperCase();
exports.assertAllowedWorkerMethod = name => {
  if (!ALLOWED.has(name)) throw new Error("worker_method_rejected");
  return name;
};
const invoke = async (service, name, ...args) => {
  exports.assertAllowedWorkerMethod(name);
  if (typeof service[name] !== "function") throw new Error("worker_contract_mismatch");
  return service[name](...args);
};
const blocked = (reasonCode, callsBeforeOpen = []) => ({
  status: "compatibility_blocked", reasonCode, validation: null,
  callsBeforeOpen, nativeProtectionAuthenticated: false,
  workerSetPathsCalled: callsBeforeOpen.includes("setPaths")
});
const unwrapList = (value, field) => {
  if (!value || value.success !== true || !Array.isArray(value[field])) {
    throw new Error("worker_contract_mismatch");
  }
  return value[field];
};
const inside = (child, root) => {
  const relative = path.relative(root, child);
  return relative && relative !== ".." &&
    !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative);
};
const keyOf = value => path.normalize(value).toLowerCase();
const databasePath = (entry, dbStorageDir) => {
  if (typeof entry !== "string" || !entry) {
    throw new Error("worker_database_path_rejected");
  }
  const root = fs.realpathSync.native(path.resolve(dbStorageDir));
  const candidate = path.resolve(root, entry);
  if (!inside(candidate, root)) {
    throw new Error("worker_database_path_rejected");
  }
  const info = fs.lstatSync(candidate);
  if (info.isSymbolicLink() || !info.isFile()) {
    throw new Error("worker_database_path_rejected");
  }
  const absolute = fs.realpathSync.native(candidate);
  if (!inside(absolute, root)) throw new Error("worker_database_path_rejected");
  return {absolute, relative: path.relative(root, absolute).replaceAll("\\", "/")};
};
const discoverDatabaseFiles = root => {
  const found = [];
  const visit = directory => {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const target = path.join(directory, entry.name);
      const info = fs.lstatSync(target);
      if (info.isSymbolicLink()) throw new Error("worker_database_path_rejected");
      if (entry.isDirectory()) visit(target);
      else if (entry.isFile() && /\.(?:db|sqlite|sqlite3)$/i.test(entry.name)) {
        found.push(databasePath(target, root));
      }
    }
  };
  visit(root);
  return found.sort((left, right) => left.relative.localeCompare(right.relative));
};
const OFFICIAL_FOLDER_KINDS = new Set([
  "bizchat", "contact", "emoticon", "favorite", "general",
  "hardlink", "head_image", "migrate", "session", "sns", "solitaire"
]);
const knownKind = relative => {
  const value = relative.toLowerCase();
  const folder = value.split("/")[0];
  if (OFFICIAL_FOLDER_KINDS.has(folder)) return folder;
  const name = path.posix.basename(value);
  if (name === "session.db") return "session";
  if (name === "contact.db") return "contact";
  if (name === "emoticon.db") return "emoticon";
  if (name === "sns.db") return "sns";
  if (name === "hardlink.db") return "hardlink";
  return null;
};
const fallbackKind = relative =>
  knownKind(relative) ||
  (relative.toLowerCase().split("/")[0] === "message" ?
    "message" : null);
const sessionId = value => typeof value === "string" ? value : value &&
  (value.sessionId || value.session_id || value.username || value.id);
const timestamp = (value, names) => {
  for (const name of names) if (value[name] !== undefined && value[name] !== null) {
    const parsed = Number(value[name]);
    if (!Number.isSafeInteger(parsed)) throw new Error("worker_contract_mismatch");
    return parsed;
  }
  return null;
};
const plainObject = value => value && typeof value === "object" &&
  !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const contactUsernames = value => {
  if (!value || value.success !== true || !Array.isArray(value.contacts)) {
    throw new Error("worker_contract_mismatch");
  }
  const usernames = value.contacts.map(contact => {
    if (!plainObject(contact)) throw new Error("worker_contract_mismatch");
    const descriptor = Object.getOwnPropertyDescriptor(contact, "username");
    if (!descriptor || !Object.hasOwn(descriptor, "value") ||
        typeof descriptor.value !== "string" ||
        descriptor.value.trim().length === 0) {
      throw new Error("worker_contract_mismatch");
    }
    return descriptor.value.trim();
  });
  if (new Set(usernames).size !== usernames.length) {
    throw new Error("worker_contract_mismatch");
  }
  return usernames;
};
const coverageMap = (value, expected) => {
  if (!value || value.success !== true || !plainObject(value.map)) {
    throw new Error("worker_contract_mismatch");
  }
  const allowed = new Set(expected);
  const result = new Set();
  for (const name of Reflect.ownKeys(value.map)) {
    const descriptor = Object.getOwnPropertyDescriptor(value.map, name);
    if (typeof name !== "string" || !allowed.has(name) || !descriptor ||
        !Object.hasOwn(descriptor, "value") ||
        typeof descriptor.value !== "string") {
      throw new Error("worker_contract_mismatch");
    }
    if (descriptor.value.trim().length > 0) result.add(name);
  }
  return result;
};
const loadCoverage = async (service, method, usernames) => {
  const found = new Set();
  for (let offset = 0; offset < usernames.length; offset += 320) {
    const batch = usernames.slice(offset, offset + 320);
    const current = coverageMap(
      await invoke(service, method, batch), batch);
    for (const name of current) found.add(name);
  }
  return found;
};

const sameFile = (...values) => new Set(values.map(value =>
  `${value.dev}:${value.ino}:${value.size}`)).size === 1;
const mediaRoot = (accountDir, ...parts) => {
  const candidate = path.join(accountDir, ...parts);
  const before = fs.lstatSync(candidate);
  if (before.isSymbolicLink() || !before.isDirectory()) {
    throw new Error("media_path_rejected");
  }
  const root = fs.realpathSync.native(candidate);
  const after = fs.lstatSync(root);
  if (after.isSymbolicLink() || !after.isDirectory() ||
      before.dev !== after.dev || before.ino !== after.ino) {
    throw new Error("media_path_rejected");
  }
  return root;
};
const readMediaPrefix = (candidate, root) => {
  let descriptor = null;
  try {
    if (typeof candidate !== "string" || !path.isAbsolute(candidate)) {
      throw new Error("media_path_rejected");
    }
    const before = fs.lstatSync(candidate);
    if (before.isSymbolicLink() || !before.isFile()) {
      throw new Error("media_path_rejected");
    }
    const absolute = fs.realpathSync.native(candidate);
    if (!inside(absolute, root)) throw new Error("media_path_rejected");
    descriptor = fs.openSync(absolute, "r");
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || !sameFile(before, opened)) {
      throw new Error("media_path_rejected");
    }
    const buffer = Buffer.alloc(32);
    const length = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(absolute);
    if (named.isSymbolicLink() || !named.isFile() ||
        !sameFile(before, opened, after, named)) {
      throw new Error("media_path_rejected");
    }
    return buffer.subarray(0, length);
  } finally {
    if (descriptor !== null) fs.closeSync(descriptor);
  }
};
const recognizedImage = prefix =>
  (prefix.length >= 3 && prefix[0] === 0xFF && prefix[1] === 0xD8 &&
    prefix[2] === 0xFF) ||
  (prefix.length >= 8 && prefix.subarray(0, 8).equals(
    Buffer.from("89504E470D0A1A0A", "hex"))) ||
  (prefix.length >= 12 && prefix.subarray(0, 4).toString("ascii") === "RIFF" &&
    prefix.subarray(8, 12).toString("ascii") === "WEBP");
const recognizedVideo = prefix =>
  recognizedImage(prefix) ||
  (prefix.length >= 12 && prefix.subarray(4, 8).toString("ascii") === "ftyp");
const parseXorKey = value => {
  if (Number.isInteger(value) && value >= 0 && value <= 255) return value;
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[a-f0-9]{1,2}$/.test(normalized)) return null;
  return Number.parseInt(normalized, 16);
};
const decodeImagePrefix = (prefix, xorKey, aesKey) => {
  if (recognizedImage(prefix)) return prefix;
  const v4Magic = Buffer.from([7, 8, 86, 50, 8, 7]);
  if (prefix.length >= 31 && prefix.subarray(0, 6).equals(v4Magic)) {
    const aesSize = prefix.readInt32LE(6);
    if (aesSize <= 0 || typeof aesKey !== "string" || aesKey.length < 16) {
      return prefix;
    }
    try {
      const decipher = crypto.createDecipheriv(
        "aes-128-ecb", Buffer.from(aesKey, "ascii").subarray(0, 16), null);
      decipher.setAutoPadding(false);
      return Buffer.concat([
        decipher.update(prefix.subarray(15, 31)),
        decipher.final()
      ]);
    } catch {
      return prefix;
    }
  }
  const key = parseXorKey(xorKey);
  if (key === null) return prefix;
  return Buffer.from([...prefix].map(byte => byte ^ key));
};
const fixedMd5 = value => typeof value === "string" &&
  /^[a-f0-9]{16,64}$/i.test(value) ? value.toLowerCase() : null;
const fixedVideoToken = value => typeof value === "string" &&
  /^[a-f0-9]{16,64}(?:_raw)?$/i.test(value) ? value.toLowerCase() : null;
const buildMediaIndex = root => {
  const files = new Map();
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const target = path.join(directory, entry.name);
      const info = fs.lstatSync(target);
      if (info.isSymbolicLink()) throw new Error("media_path_rejected");
      if (entry.isDirectory()) {
        const absolute = fs.realpathSync.native(target);
        if (!inside(absolute, root)) throw new Error("media_path_rejected");
        pending.push(absolute);
      } else if (entry.isFile()) {
        const name = path.parse(entry.name).name.toLowerCase();
        if (!files.has(name)) files.set(name, []);
        files.get(name).push(target);
      } else {
        throw new Error("media_path_rejected");
      }
    }
  }
  return files;
};
const indexedMedia = (index, token) => {
  const matches = [
    ...(index.get(token) || []),
    ...(index.get(`${token}_thumb`) || [])
  ];
  if (matches.length > 1) return null;
  return matches[0] || null;
};
const mediaCandidateIdentity = item => {
  if (!plainObject(item) ||
      !["image", "video"].includes(item.mediaType) ||
      typeof item.sessionId !== "string" || !item.sessionId ||
      !Number.isSafeInteger(item.localId) || item.localId < 0 ||
      !Number.isSafeInteger(item.localType) ||
      !Number.isSafeInteger(item.createTime) || item.createTime < 0) {
    throw new Error("worker_contract_mismatch");
  }
  return JSON.stringify([
    item.sessionId, item.localId, item.localType,
    item.createTime, item.mediaType
  ]);
};
const inspectImageCandidate = async (
  service, item, accountDir, attachRoot, attachIndex,
  imageXorKey, imageAesKey, mark
) => {
  const md5 = fixedMd5(item.imageMd5);
  mark("media_image_md5_ready");
  let candidate = null;
  if (md5) {
    mark("media_image_hardlink_started");
    const resolved = await invoke(
      service, "resolveImageHardlink", md5, accountDir);
    mark("media_image_hardlink_ready");
    if (resolved && resolved.success === true) {
      mark("media_image_hardlink_success");
      if (!plainObject(resolved.data)) {
        throw new Error("worker_contract_mismatch");
      }
      mark("media_image_hardlink_data_ready");
      if (resolved.data.file_name != null || resolved.data.full_path != null) {
        if (typeof resolved.data.file_name !== "string" ||
            !resolved.data.file_name) {
          throw new Error("worker_contract_mismatch");
        }
        mark("media_image_hardlink_filename_ready");
        if (typeof resolved.data.full_path !== "string" ||
            !resolved.data.full_path) {
          throw new Error("worker_contract_mismatch");
        }
        mark("media_image_hardlink_fullpath_ready");
        if (path.basename(resolved.data.full_path) !== resolved.data.file_name) {
          throw new Error("worker_contract_mismatch");
        }
        mark("media_image_hardlink_basename_matched");
        candidate = resolved.data.full_path;
      }
    }
    mark("media_image_hardlink_validated");
  }
  const datName = typeof item.imageDatName === "string" ?
    item.imageDatName.replace(/\.dat$/i, "") : null;
  const token = fixedMd5(datName) || md5;
  mark("media_image_token_ready");
  if (candidate === null && token) {
    candidate = indexedMedia(attachIndex, token);
    mark("media_image_index_lookup_ready");
  }
  if (candidate === null) {
    mark("media_image_unavailable");
    return null;
  }
  mark("media_image_candidate_selected");
  const prefix = readMediaPrefix(candidate, attachRoot);
  mark("media_image_prefix_read");
  const decoded = decodeImagePrefix(
    prefix,
    imageXorKey,
    imageAesKey
  );
  mark("media_image_prefix_decoded");
  return decoded;
};
const inspectVideoCandidate = async (
  service, item, dbStorageDir, videoRoot, videoIndex
) => {
  const md5 = fixedMd5(item.videoMd5);
  if (!md5) return null;
  const hardlinkDb = databasePath(
    path.join("hardlink", "hardlink.db"), dbStorageDir).absolute;
  const resolved = await invoke(
    service, "resolveVideoHardlinkMd5", md5, hardlinkDb);
  if (!resolved || resolved.success !== true) return null;
  const token = fixedVideoToken(resolved.data && resolved.data.resolved_md5);
  if (!token) throw new Error("worker_contract_mismatch");
  const candidate = indexedMedia(videoIndex, token);
  return candidate === null ? null : readMediaPrefix(candidate, videoRoot);
};

exports.runMediaOpenabilityGateway = async function (service, request) {
  const callsBeforeOpen = [];
  const mark = typeof request.markStage === "function" ?
    request.markStage : () => {};
  mark("media_gateway_started");
  const accountDir = path.dirname(request.dbStorageDir);
  await invoke(service, "setPaths", request.resourcesPath, request.userDataDir);
  mark("paths_set");
  callsBeforeOpen.push("setPaths");
  const tested = await invoke(service, "testConnection",
                              accountDir, request.syntheticHexKey);
  mark("connection_tested");
  callsBeforeOpen.push("testConnection");
  if (!tested || tested.success !== true) {
    return blocked("connection_failed", callsBeforeOpen);
  }
  const opened = await invoke(service, "open", accountDir, request.syntheticHexKey);
  mark("account_opened");
  if (opened !== true) return blocked("open_failed", callsBeforeOpen);
  try {
    const sessions = unwrapList(
      await invoke(service, "getSessions"), "sessions").map(sessionId);
    if (sessions.some(value => typeof value !== "string" || !value) ||
        new Set(sessions).size !== sessions.length) {
      throw new Error("worker_contract_mismatch");
    }
    mark("sessions_loaded");
    const totals = await invoke(service, "getAggregateStats", sessions, 0, 0);
    const nativeTotal = Number(totals && totals.data && totals.data.total);
    if (!totals || totals.success !== true || !Number.isSafeInteger(nativeTotal) ||
        nativeTotal < 0) throw new Error("worker_contract_mismatch");
    mark("aggregate_loaded");
    const attachRoot = mediaRoot(accountDir, "msg", "attach");
    const videoRoot = mediaRoot(accountDir, "msg", "video");
    mark("media_index_started");
    const attachIndex = buildMediaIndex(attachRoot);
    const videoIndex = buildMediaIndex(videoRoot);
    mark("media_index_ready");
    const counts = {
      version: 1,
      candidateCount: 0,
      imageCandidateCount: 0,
      videoCandidateCount: 0,
      locallyUnavailableCount: 0,
      localFileCount: 0,
      readableImageCount: 0,
      readableVideoCount: 0,
      unreadableLocalCount: 0
    };
    const seen = new Set();
    let offset = 0;
    mark("media_stream_started");
    for (let pageNumber = 0; pageNumber <= nativeTotal; pageNumber += 1) {
      const page = await invoke(service, "getMediaStream", {
        sessionId: "", mediaType: "all", beginTimestamp: 0, endTimestamp: 0,
        offset, limit: 240
      });
      if (!plainObject(page) || page.success !== true ||
          !Array.isArray(page.items) || typeof page.hasMore !== "boolean" ||
          !Number.isSafeInteger(page.nextOffset) ||
          page.nextOffset !== offset + page.items.length ||
          (page.hasMore && page.items.length === 0)) {
        throw new Error("worker_contract_mismatch");
      }
      mark("media_stream_page_loaded");
      for (const item of page.items) {
        const identity = mediaCandidateIdentity(item);
        mark("media_candidate_identity_ready");
        if (seen.has(identity)) throw new Error("worker_contract_mismatch");
        seen.add(identity);
        mark("media_candidate_unique");
        counts.candidateCount += 1;
        const image = item.mediaType === "image";
        counts[image ? "imageCandidateCount" : "videoCandidateCount"] += 1;
        mark(image ? "media_image_inspect_started" :
          "media_video_inspect_started");
        const prefix = image ?
          await inspectImageCandidate(
            service, item, accountDir, attachRoot, attachIndex,
            request.imageXorKey, request.imageAesKey, mark) :
          await inspectVideoCandidate(
            service, item, request.dbStorageDir, videoRoot, videoIndex);
        mark(image ? "media_image_inspect_ready" :
          "media_video_inspect_ready");
        if (prefix === null) {
          counts.locallyUnavailableCount += 1;
        } else {
          counts.localFileCount += 1;
          const readable = image ? recognizedImage(prefix) : recognizedVideo(prefix);
          if (readable) {
            counts[image ? "readableImageCount" : "readableVideoCount"] += 1;
          } else {
            counts.unreadableLocalCount += 1;
          }
        }
        mark("media_candidate_counted");
      }
      offset = page.nextOffset;
      if (!page.hasMore) {
        mark("media_probe_ready");
        return {
          status: "ok", reasonCode: null, mediaOpenability: counts,
          callsBeforeOpen, nativeProtectionAuthenticated: true,
          workerSetPathsCalled: true
        };
      }
    }
    throw new Error("worker_contract_mismatch");
  } catch {
    return blocked("media_probe_failed", callsBeforeOpen);
  }
};

exports.runAvatarAggregateGateway = async function (service, request) {
  const callsBeforeOpen = [];
  const mark = typeof request.markStage === "function" ?
    request.markStage : () => {};
  mark("avatar_gateway_started");
  const accountDir = path.dirname(request.dbStorageDir);
  await invoke(service, "setPaths", request.resourcesPath, request.userDataDir);
  mark("paths_set");
  callsBeforeOpen.push("setPaths");
  const tested = await invoke(service, "testConnection",
                              accountDir, request.syntheticHexKey);
  mark("connection_tested");
  callsBeforeOpen.push("testConnection");
  if (!tested || tested.success !== true) {
    return blocked("connection_failed", callsBeforeOpen);
  }
  const opened = await invoke(service, "open",
                              accountDir, request.syntheticHexKey);
  mark("account_opened");
  if (opened !== true) return blocked("open_failed", callsBeforeOpen);
  const usernames = contactUsernames(
    await invoke(service, "getContactsCompact", []));
  mark("contacts_loaded");
  const avatarUrls = await loadCoverage(
    service, "getAvatarUrls", usernames);
  mark("avatar_urls_loaded");
  const headImageBuffers = await loadCoverage(
    service, "getHeadImageBuffers", usernames);
  mark("head_image_buffers_loaded");
  const avatarAggregate = sanitizeAvatarAggregate(aggregateAvatarCoverage(
    usernames.map(name => ({
      hasAvatarUrl: avatarUrls.has(name),
      hasHeadImageBuffer: headImageBuffers.has(name),
    }))
  ));
  mark("avatar_aggregate_ready");
  return {
    status: "ok",
    reasonCode: null,
    avatarAggregate,
    callsBeforeOpen,
    nativeProtectionAuthenticated: true,
    workerSetPathsCalled: true,
  };
};

exports.runSnapshotGateway = async function (service, request) {
  const callsBeforeOpen = [];
  const mark = typeof request.markStage === "function" ?
    request.markStage : () => {};
  mark("gateway_started");
  const accountDir = path.dirname(request.dbStorageDir);
  await invoke(service, "setPaths", request.resourcesPath, request.userDataDir);
  mark("paths_set");
  callsBeforeOpen.push("setPaths");
  const tested = await invoke(service, "testConnection",
                              accountDir, request.syntheticHexKey);
  mark("connection_tested");
  callsBeforeOpen.push("testConnection");
  if (!tested || tested.success !== true) return blocked("connection_failed", callsBeforeOpen);
  const opened = await invoke(service, "open",
                              accountDir, request.syntheticHexKey);
  mark("account_opened");
  if (opened !== true) return blocked("open_failed", callsBeforeOpen);
  const sessions = unwrapList(await invoke(service, "getSessions"), "sessions")
    .map(sessionId);
  if (sessions.some(value => typeof value !== "string" || !value) ||
      new Set(sessions).size !== sessions.length) {
    throw new Error("worker_contract_mismatch");
  }
  mark("sessions_loaded");
  const totals = await invoke(service, "getAggregateStats", sessions, 0, 0);
  const nativeTotal = Number(totals && totals.data && totals.data.total);
  if (!totals || totals.success !== true || !Number.isSafeInteger(nativeTotal) ||
      nativeTotal < 0) return blocked("aggregate_failed", callsBeforeOpen);
  mark("aggregate_loaded");

  const tableStats = new Map();
  let tableStatsTotal = 0;
  for (const id of sessions) {
    const rows = unwrapList(
      await invoke(service, "getMessageTableStats", id), "tables");
    for (const row of rows) {
      const db = databasePath(row && (row.db_path || row.dbPath), request.dbStorageDir);
      const name = row && (row.table_name || row.tableName || row.name);
      const count = Number(row && (row.count ?? row.message_count ?? row.messageCount));
      if (typeof name !== "string" || !name || !Number.isSafeInteger(count) || count < 0) {
        throw new Error("worker_contract_mismatch");
      }
      const key = `${keyOf(db.absolute)}\0${name}`;
      if (tableStats.has(key)) {
        throw new Error("worker_contract_mismatch");
      }
      tableStatsTotal += count;
      if (!Number.isSafeInteger(tableStatsTotal)) {
        throw new Error("worker_contract_mismatch");
      }
      tableStats.set(key, count);
    }
  }
  mark("message_stats_loaded");
  if (tableStatsTotal !== nativeTotal) {
    throw new Error("worker_contract_mismatch");
  }

  const listedKinds = new Map();
  for (const [method, kind] of [["listMessageDbs", "message"],
                                ["listMediaDbs", "media"]]) {
    mark(`${kind}_list_started`);
    const listed = unwrapList(await invoke(service, method), "data");
    mark(`${kind}_list_loaded`);
    for (const entry of listed) {
      let db;
      try {
        db = databasePath(entry, request.dbStorageDir);
      } catch (error) {
        mark(`${kind}_entry_path_rejected`);
        throw error;
      }
      const key = keyOf(db.absolute);
      if (listedKinds.has(key)) {
        mark(`${kind}_list_conflict`);
        throw new Error("worker_contract_mismatch");
      }
      if (knownKind(db.relative) &&
          knownKind(db.relative) !== kind) {
        mark(`${kind}_kind_conflict`);
        throw new Error("worker_contract_mismatch");
      }
      listedKinds.set(key, kind);
    }
    mark(`${kind}_list_validated`);
  }
  mark("database_lists_loaded");
  const discovered = discoverDatabaseFiles(request.dbStorageDir);
  mark("database_files_discovered");
  const discoveredKeys = new Set(discovered.map(db => keyOf(db.absolute)));
  if ([...listedKinds.keys()].some(key => !discoveredKeys.has(key))) {
    throw new Error("worker_database_set_mismatch");
  }
  const databases = [];
  const consumedTableStats = new Set();
  for (const db of discovered) {
    const dynamicKind = listedKinds.get(keyOf(db.absolute));
    const kind = dynamicKind ||
      fallbackKind(db.relative);
    if (!kind) {
      mark("database_unclassified");
      throw new Error("worker_database_unclassified");
    }
    mark("tables_list_started");
    const names = unwrapList(
      await invoke(service, "listTables", kind, db.absolute), "tables");
    mark("tables_list_loaded");
    if (names.some(name => typeof name !== "string" || !name) ||
        new Set(names).size !== names.length) {
      throw new Error("worker_contract_mismatch");
    }
    const tables = [];
    for (const name of names) {
      mark("table_schema_started");
      const schema = await invoke(service, "getTableSchema", kind, db.absolute, name);
      mark("table_schema_loaded");
      if (!schema || schema.success !== true) {
        mark("table_schema_failed");
        throw new Error("worker_contract_mismatch");
      }
      if (typeof schema.schema !== "string" || !schema.schema) {
        mark("table_schema_empty");
        throw new Error("worker_contract_mismatch");
      }
      let recordCount = null, minTimestamp = null, maxTimestamp = null;
      if (kind === "message" && tableStats.has(
        `${keyOf(db.absolute)}\0${name}`)) {
        const statKey = `${keyOf(db.absolute)}\0${name}`;
        recordCount = tableStats.get(statKey);
        consumedTableStats.add(statKey);
        const range = await invoke(service, "getMessageTableTimeRange",
                                   db.absolute, name);
        if (!range || range.success !== true || !range.data) {
          throw new Error("worker_contract_mismatch");
        }
        minTimestamp = timestamp(range.data,
          ["first_ts", "firstTs", "min_ts", "minTs"]);
        maxTimestamp = timestamp(range.data,
          ["last_ts", "lastTs", "max_ts", "maxTs"]);
      }
      tables.push({name, schemaHash: digest(schema.schema), recordCount,
                   minTimestamp, maxTimestamp});
    }
    databases.push({relativePath: db.relative, kind, tables});
    mark("database_scanned");
  }
  if (consumedTableStats.size !== tableStats.size) {
    throw new Error("worker_contract_mismatch");
  }
  mark("fingerprints_ready");
  return {status: "ok", reasonCode: null,
    validation: aggregateValidation({
      sourceAccountName: request.sourceAccountName, databases, nativeTotal}),
    callsBeforeOpen, nativeProtectionAuthenticated: true,
    workerSetPathsCalled: true};
};
exports.exportedGateway = () => Object.freeze({
  runAvatarAggregateGateway: exports.runAvatarAggregateGateway,
  runSnapshotGateway: exports.runSnapshotGateway
});
