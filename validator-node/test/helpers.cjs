const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const HEX_KEY = "AB".repeat(32);

exports.createJunctionFixture = t => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "wf-path-"));
  const runRoot = path.join(base, "run");
  const outside = path.join(base, "outside");
  fs.mkdirSync(path.join(outside, "wxid_test"), {recursive: true});
  fs.mkdirSync(runRoot, {recursive: true});
  fs.symlinkSync(outside, path.join(runRoot, "validation"), "junction");
  t.after(() => fs.rmSync(base, {recursive: true, force: true}));
  return {runRoot, sourceAccountName: "wxid_test"};
};

exports.createRoleFixture = t => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "wf-role-"));
  const runRoot = path.join(base, "run");
  const roleRoot = path.join(runRoot, "validation");
  const accountRoot = path.join(roleRoot, "wxid_test");
  const dbStorage = path.join(accountRoot, "db_storage");
  fs.mkdirSync(dbStorage, {recursive: true});
  t.after(() => fs.rmSync(base, {recursive: true, force: true}));
  return {
    runRoot,
    roleRoot,
    accountRoot,
    dbStorage,
    sourceAccountName: "wxid_test"
  };
};

exports.fakeRequest = t => {
  const fixture = exports.createRoleFixture(t);
  const message = path.join(fixture.dbStorage, "message", "message_0.db");
  const media = path.join(fixture.dbStorage, "media", "media_0.db");
  fs.mkdirSync(path.dirname(message), {recursive: true});
  fs.mkdirSync(path.dirname(media), {recursive: true});
  fs.writeFileSync(message, "synthetic-message");
  fs.writeFileSync(media, "synthetic-media");
  return {
    resourcesPath: path.join(
      fixture.runRoot,
      "runtime",
      "WeFlow",
      "resources",
      "resources"
    ),
    userDataDir: path.join(fixture.runRoot, "profile"),
    dbStorageDir: fixture.dbStorage,
    sourceAccountName: fixture.sourceAccountName,
    syntheticHexKey: HEX_KEY
  };
};

exports.fakeService = (calls, request) => ({
  setPaths(...args) {
    calls.push({name: "setPaths", args});
  },
  async testConnection(...args) {
    calls.push({name: "testConnection", args});
    return {success: true};
  },
  async open(...args) {
    calls.push({name: "open", args});
    return true;
  },
  async getSessions(...args) {
    calls.push({name: "getSessions", args});
    return {success: true, sessions: [{id: "synthetic-session"}]};
  },
  async getAggregateStats(...args) {
    calls.push({name: "getAggregateStats", args});
    return {success: true, data: {total: 0, sessions: {}}};
  },
  async listMessageDbs(...args) {
    calls.push({name: "listMessageDbs", args});
    return {
      success: true,
      data: [path.join(request.dbStorageDir, "message", "message_0.db")]
    };
  },
  async listMediaDbs(...args) {
    calls.push({name: "listMediaDbs", args});
    return {
      success: true,
      data: [path.join(request.dbStorageDir, "media", "media_0.db")]
    };
  },
  async listTables(...args) {
    calls.push({name: "listTables", args});
    return {
      success: true,
      tables: [String(args[0]) === "message" ? "message" : "media"]
    };
  },
  async getTableSchema(...args) {
    calls.push({name: "getTableSchema", args});
    return {
      success: true,
      schema: "CREATE TABLE synthetic(id INTEGER)"
    };
  },
  async getMessageTableStats(...args) {
    calls.push({name: "getMessageTableStats", args});
    return {
      success: true,
      tables: [{
        db_path: path.join(
          request.dbStorageDir,
          "message",
          "message_0.db"
        ),
        table_name: "message",
        count: 0
      }]
    };
  },
  async getMessageTableTimeRange(...args) {
    calls.push({name: "getMessageTableTimeRange", args});
    return {
      success: true,
      data: {first_ts: null, last_ts: null}
    };
  }
});

exports.validValidationResult = () => ({
  version: 1,
  runId: "00000000-0000-4000-8000-000000000001",
  operation: "validate-snapshot",
  status: "ok",
  reasonCode: null,
  gates: {
    userDataIsolated: true,
    documentsIsolated: true,
    singleInstanceLockAcquired: true,
    safeStorageAvailable: true,
    syntheticEnvelopeRoundtrip: false,
    nativeProtectionAuthenticated: true,
    workerSetPathsCalled: true
  },
  validation: {
    databaseCount: 2,
    tableCount: 3,
    recordCount: 5,
    minTimestamp: 1,
    maxTimestamp: 5,
    schemaFingerprint: "A".repeat(64),
    aggregateFingerprint: "B".repeat(64),
    databaseCoverageFingerprint: "C".repeat(64)
  },
  callsBeforeOpen: ["setPaths", "testConnection"]
});

exports.coverageFixture = () => {
  const message = {
    relativePath: "message/message_0.db",
    kind: "message",
    tables: [{
      name: "message",
      schemaHash: "D".repeat(64),
      recordCount: 5,
      minTimestamp: 1,
      maxTimestamp: 5
    }]
  };
  const emptyMedia = {
    relativePath: "media/media_0.db",
    kind: "media",
    tables: []
  };
  return {
    complete: {
      sourceAccountName: "synthetic",
      databases: [message, emptyMedia],
      nativeTotal: 5
    },
    missing: {
      sourceAccountName: "synthetic",
      databases: [message],
      nativeTotal: 5
    }
  };
};
