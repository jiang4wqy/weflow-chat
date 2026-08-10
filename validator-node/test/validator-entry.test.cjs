const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  prepareBoot, _electronPathsMatchForTest, _prepareBootForTest,
  _atomicWriteForTest, _roundtripSupportedEncryptedFieldForTest,
  _runValidatorForTest
} = require("../src/validator-entry.cjs");
const {
  assertAllowedWorkerMethod, exportedGateway, runSnapshotGateway
} = require("../src/worker-gateway.cjs");
const {
  fakeRequest, fakeService, validValidationResult
} = require("./helpers.cjs");

const RUN_ID = "00000000-0000-4000-8000-000000000001";
const ATTEMPT_ID = "00000000-0000-4000-8000-000000000002";
const RUN_NAME = `20260721-000000-${RUN_ID}`;

test("Task 4 entry bytes match the JavaScript copied-module contract",
     async () => {
  const expected =
    "2800CF8946B2C8846EBE8F29938C822C8CB96D092D19B8F6303BDE4878720CC3";
  const raw = fs.readFileSync(
    path.join(__dirname, "..", "src", "validator-entry.cjs"));
  assert.equal(raw.length, 17543);
  assert.equal(require("node:crypto").createHash("sha256").update(raw)
    .digest("hex").toUpperCase(), expected);
  const patcher = await import("../src/extract-and-patch.mjs");
  assert.equal(
    patcher._copiedModuleContractForTest()["validator-entry.cjs"],
    expected);
});

test("Task 4 worker bytes match the JavaScript copied-module contract",
     async () => {
  const expected =
    "109E9C4D29124947BCC6DF124710FE9D70F28C6543FB81B1D60F63FCE42AFEBE";
  const raw = fs.readFileSync(
    path.join(__dirname, "..", "src", "worker-gateway.cjs"));
  assert.equal(raw.length, 27645);
  assert.equal(require("node:crypto").createHash("sha256").update(raw)
    .digest("hex").toUpperCase(), expected);
  const patcher = await import("../src/extract-and-patch.mjs");
  assert.equal(
    patcher._copiedModuleContractForTest()["worker-gateway.cjs"],
    expected);
});

function bootFixture(t, {names = {}, linkIndex = null} = {}) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "wf-entry-"));
  t.after(() => fs.rmSync(base, {recursive: true, force: true}));
  const snapshotsRoot = path.join(base, "Snapshots");
  fs.mkdirSync(snapshotsRoot);
  const parts = [names.run || RUN_NAME, names.validator || "validator",
    names.area || "validation", names.attempt || ATTEMPT_ID,
    names.request || "request"];
  let lexical = snapshotsRoot;
  for (let index = 0; index < parts.length; index += 1) {
    const lexicalChild = path.join(lexical, parts[index]);
    if (index === linkIndex) {
      const target = path.join(base, `outside-${index}`, parts[index]);
      fs.mkdirSync(target, {recursive: true});
      try {
        fs.symlinkSync(target, lexicalChild, "junction");
      } catch (error) {
        if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
          t.skip("junction creation unavailable");
          return null;
        }
        throw error;
      }
    } else {
      fs.mkdirSync(lexicalChild);
    }
    lexical = lexicalChild;
  }
  const attempt = path.dirname(lexical);
  for (const name of ["profile", "documents", "cache", "result"]) {
    fs.mkdirSync(path.join(attempt, name), {recursive: true});
  }
  const requestPath = path.join(lexical, "request.json");
  const requestBytes = JSON.stringify({
    operation: "safe-envelope-roundtrip", runId: RUN_ID
  });
  if (linkIndex === parts.length) {
    const target = path.join(base, "outside-request.json");
    fs.writeFileSync(target, requestBytes);
    try {
      fs.symlinkSync(target, requestPath, "file");
    } catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
        t.skip("file symlink creation unavailable");
        return null;
      }
      throw error;
    }
  } else {
    fs.writeFileSync(requestPath, requestBytes);
  }
  const resourcesPath = path.join(
    snapshotsRoot, parts[0], "runtime", "WeFlow", "resources");
  fs.mkdirSync(resourcesPath, {recursive: true});
  const paths = new Map();
  const app = {
    setPath: (name, value) => paths.set(name, value),
    getPath: name => paths.get(name)
  };
  return {requestPath, resourcesPath, snapshotsRoot, app, env: {}, paths};
}

test("entry binds the full run validator area attempt ancestry", t => {
  const fixture = bootFixture(t);
  const boot = _prepareBootForTest({
    app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request", fixture.requestPath],
    env: fixture.env, resourcesPath: fixture.resourcesPath
  }, fixture.snapshotsRoot);
  assert.equal(path.basename(boot.runRoot), RUN_NAME);
  assert.equal(path.basename(path.dirname(boot.attemptRoot)), "validation");
  assert.equal(path.basename(path.dirname(path.dirname(boot.attemptRoot))),
               "validator");
});

test("entry accepts presentation only for validate-snapshot ancestry", t => {
  const fixture = bootFixture(t, {names: {area: "presentation"}});
  fs.writeFileSync(fixture.requestPath, JSON.stringify({
    operation: "validate-snapshot", runId: RUN_ID, area: "presentation"
  }));

  const boot = _prepareBootForTest({
    app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request", fixture.requestPath],
    env: fixture.env,
    resourcesPath: fixture.resourcesPath
  }, fixture.snapshotsRoot);

  assert.equal(boot.request.area, "presentation");
  assert.equal(path.basename(path.dirname(boot.attemptRoot)), "presentation");
});

test("entry accepts media openability only under presentation ancestry", t => {
  const fixture = bootFixture(t, {names: {area: "presentation"}});
  fs.writeFileSync(fixture.requestPath, JSON.stringify({
    operation: "media-openability", runId: RUN_ID, area: "presentation"
  }));

  const boot = _prepareBootForTest({
    app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request", fixture.requestPath],
    env: fixture.env,
    resourcesPath: fixture.resourcesPath
  }, fixture.snapshotsRoot);

  assert.equal(boot.request.operation, "media-openability");
  assert.equal(boot.request.area, "presentation");
});

for (const [name, names] of [
  ["run", {run: `wrong-${ATTEMPT_ID}`}],
  ["validator", {validator: "other"}],
  ["area", {area: "other"}],
  ["attempt", {attempt: "not-a-guid"}],
  ["request", {request: "other"}],
]) {
  test(`entry rejects wrong ${name} ancestry`, t => {
    const fixture = bootFixture(t, {names});
    assert.throws(() => _prepareBootForTest({app: fixture.app,
      argv: ["WeFlow.exe", "--weflow-validator-request",
             fixture.requestPath], env: fixture.env,
      resourcesPath: fixture.resourcesPath}, fixture.snapshotsRoot),
      /request_(?:path|ancestry|run_id)_(?:rejected|invalid)/);
  });
}

for (const [index, name] of [
  "run", "validator", "area", "attempt", "request", "request-file"
].entries()) {
  test(`entry rejects a ${name} link component`, t => {
    const fixture = bootFixture(t, {linkIndex: index});
    if (fixture === null) return;
    assert.throws(() => _prepareBootForTest({app: fixture.app,
      argv: ["WeFlow.exe", "--weflow-validator-request",
             fixture.requestPath], env: fixture.env,
      resourcesPath: fixture.resourcesPath}, fixture.snapshotsRoot),
      /request_reparse_rejected/);
  });
}

test("production rejects a fake run outside the fixed Snapshots root", t => {
  const fixture = bootFixture(t);
  assert.throws(() => prepareBoot({app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request",
           fixture.requestPath], env: fixture.env,
    resourcesPath: fixture.resourcesPath}),
    /request_snapshots_root_rejected/);
});

test("entry rejects runtime resources from a different run", t => {
  const fixture = bootFixture(t);
  const other = path.join(fixture.snapshotsRoot,
    "20260721-000001-00000000-0000-4000-8000-000000000003",
    "runtime", "WeFlow", "resources");
  fs.mkdirSync(other, {recursive: true});
  assert.throws(() => _prepareBootForTest({app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request",
           fixture.requestPath], env: fixture.env,
    resourcesPath: other}, fixture.snapshotsRoot),
    /request_runtime_mismatch/);
});

test("electron path gate requires exact canonical getPath readback", t => {
  const fixture = bootFixture(t);
  const boot = _prepareBootForTest({app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request",
           fixture.requestPath], env: fixture.env,
    resourcesPath: fixture.resourcesPath}, fixture.snapshotsRoot);
  assert.equal(_electronPathsMatchForTest({app: fixture.app, boot}), true);
  const outside = path.join(path.dirname(fixture.snapshotsRoot), "outside");
  fs.mkdirSync(outside);
  fixture.app.setPath("documents", outside);
  assert.equal(_electronPathsMatchForTest({app: fixture.app, boot}), false);
});

test("result chain is rechecked after callback and before commit", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-result-"));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const directory = path.join(root, "result");
  const target = path.join(directory, "result.json");
  fs.mkdirSync(directory);
  let swapped = false;
  const chainCheck = (candidate, options = {}) => {
    if (swapped && candidate === directory) {
      throw new Error("request_reparse_rejected");
    }
    return options.requireTarget === false ? candidate :
      fs.realpathSync.native(candidate);
  };
  assert.throws(() => _atomicWriteForTest({
    target, value: validValidationResult(), chainCheck,
    beforeCommit: () => { swapped = true; }
  }), /request_reparse_rejected/);
  assert.equal(fs.existsSync(target), false);
  assert.deepEqual(fs.readdirSync(directory), []);
});

test("result publication never replaces an existing sentinel", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-result-exists-"));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const target = path.join(root, "result.json");
  fs.writeFileSync(target, "sentinel", {flag: "wx"});
  assert.throws(() => _atomicWriteForTest({
    target, value: validValidationResult()
  }), /EEXIST/);
  assert.equal(fs.readFileSync(target, "utf8"), "sentinel");
  assert.deepEqual(fs.readdirSync(root), ["result.json"]);
});

test("result publication cannot override its fixed sanitizer", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-result-sanitize-"));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const target = path.join(root, "result.json");
  assert.throws(() => _atomicWriteForTest({
    target,
    value: {
      decryptKey: "safe:forbidden",
      sourcePath: String.raw`X:\forbidden\source`
    },
    sanitizer: value => value
  }), /result_sensitive_field/);
  assert.equal(fs.existsSync(target), false);
});

test("result publication removes its temporary after callback failure", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-result-callback-"));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const target = path.join(root, "result.json");
  assert.throws(() => _atomicWriteForTest({
    target, value: validValidationResult(),
    beforeCommit: () => { throw new Error("callback_failed"); }
  }), /callback_failed/);
  assert.equal(fs.existsSync(target), false);
  assert.deepEqual(fs.readdirSync(root), []);
});

test("result publication keeps the temporary open through commit", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-result-open-"));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const target = path.join(root, "result.json");
  const attacker = path.join(root, "attacker.json");
  const value = validValidationResult();
  let replacementError = null;
  _atomicWriteForTest({
    target, value,
    beforeCommit: () => {
      const temporary = fs.readdirSync(root)
        .map(name => path.join(root, name))
        .find(name => name.endsWith(".tmp"));
      fs.writeFileSync(attacker, "attacker", {flag: "wx"});
      try {
        fs.renameSync(attacker, temporary);
      } catch (error) {
        replacementError = error;
      }
    }
  });
  assert.equal(replacementError && replacementError.code, "EPERM");
  assert.equal(fs.readFileSync(target, "utf8"), JSON.stringify(value));
  assert.equal(fs.readdirSync(root).some(name => name.endsWith(".tmp")), false);
});

test("result publication rejects an unlinked and recreated temporary", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-result-replace-"));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const target = path.join(root, "result.json");
  const attacker = path.join(root, "attacker.json");
  fs.writeFileSync(attacker, "attacker", {flag: "wx"});
  assert.throws(() => _atomicWriteForTest({
    target, value: validValidationResult(),
    beforeCommit: () => {
      const temporary = fs.readdirSync(root)
        .map(name => path.join(root, name))
        .find(name => name.endsWith(".tmp"));
      fs.rmSync(temporary);
      fs.renameSync(attacker, temporary);
    }
  }), /result_temporary_changed/);
  assert.equal(fs.existsSync(target), false);
  assert.deepEqual(fs.readdirSync(root), []);
});

test("successful result commit performs no failing post-link check", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-result-final-"));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const target = path.join(root, "result.json");
  const value = validValidationResult();
  const chainCheck = (candidate, options = {}) => {
    if (candidate === target && fs.existsSync(target) &&
        options.requireTarget !== false) {
      throw new Error("post_link_check_reached");
    }
    return options.requireTarget === false ? candidate :
      fs.realpathSync.native(candidate);
  };
  assert.doesNotThrow(() => _atomicWriteForTest({
    target, value, chainCheck
  }));
  assert.equal(fs.readFileSync(target, "utf8"), JSON.stringify(value));
  assert.deepEqual(fs.readdirSync(root), ["result.json"]);
});

test("roundtrip uses decryptKey and restores the isolated probe", async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-envelope-"));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const configPath = path.join(root, "WeFlow-config.json");
  const original = "AB".repeat(32);
  let current = original;
  const calls = [];
  const config = {
    async get(name) { calls.push(["get", name]); return current; },
    async set(name, value) {
      calls.push(["set", name, value]); current = value;
      fs.writeFileSync(configPath, JSON.stringify({
        [name]: `safe:${Buffer.from(value).toString("base64")}`
      }));
    }
  };
  await _roundtripSupportedEncryptedFieldForTest({
    config, configPath, probe: "CD".repeat(32)
  });
  assert.equal(current, original);
  assert.deepEqual(calls.map(call => call.slice(0, 2)), [
    ["get", "decryptKey"], ["set", "decryptKey"],
    ["get", "decryptKey"], ["set", "decryptKey"],
    ["get", "decryptKey"]]);
  assert.equal(fs.readFileSync(configPath, "utf8").includes("CD".repeat(32)),
               false);
});

test("roundtrip removes the isolated config if restoration fails", async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-envelope-fail-"));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const configPath = path.join(root, "WeFlow-config.json");
  const original = "AB".repeat(32);
  let current = original;
  const config = {
    async get() { return current; },
    async set(name, value) {
      if (value === original) throw new Error("restore_failed");
      current = value;
      fs.writeFileSync(configPath, JSON.stringify({
        [name]: `safe:${Buffer.from(value).toString("base64")}`
      }));
    }
  };
  await assert.rejects(
    _roundtripSupportedEncryptedFieldForTest({
      config, configPath, probe: "CD".repeat(32)
    }), /safe_envelope_roundtrip_failed/);
  assert.equal(fs.existsSync(configPath), false);
});

test("validate-snapshot follows the production resource and config chain",
     async t => {
  const fixture = bootFixture(t);
  fs.writeFileSync(fixture.requestPath, JSON.stringify({
    operation: "validate-snapshot", runId: RUN_ID, area: "validation"
  }));
  const workerResources = path.join(fixture.resourcesPath, "resources");
  fs.mkdirSync(workerResources);
  const boot = _prepareBootForTest({
    app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request", fixture.requestPath],
    env: fixture.env, resourcesPath: fixture.resourcesPath
  }, fixture.snapshotsRoot);
  const sourceAccountName = "wxid_test";
  const roleRoot = path.join(boot.runRoot, "validation");
  const dbStorageDir = path.join(roleRoot, sourceAccountName, "db_storage");
  const message = path.join(dbStorageDir, "message", "message_0.db");
  const media = path.join(dbStorageDir, "media", "media_0.db");
  fs.mkdirSync(path.dirname(message), {recursive: true});
  fs.mkdirSync(path.dirname(media), {recursive: true});
  fs.writeFileSync(message, "synthetic-message");
  fs.writeFileSync(media, "synthetic-media");
  const syntheticHexKey = "AB".repeat(32);
  const values = {
    dbPath: roleRoot,
    myWxid: sourceAccountName,
    decryptKey: syntheticHexKey,
    wxidConfigs: {
      [sourceAccountName]: {decryptKey: syntheticHexKey.toLowerCase()}
    }
  };
  const configCalls = [];
  class ConfigService {
    async get(name) {
      configCalls.push(name);
      return values[name];
    }
  }
  const calls = [];
  const service = fakeService(calls, {
    resourcesPath: workerResources,
    userDataDir: boot.userDataDir,
    dbStorageDir,
    sourceAccountName,
    syntheticHexKey
  });
  const exitCode = await _runValidatorForTest({
    boot, ConfigService, wcdbService: service,
    resourcesPath: workerResources, app: fixture.app
  }, {safeStorage: {isEncryptionAvailable: () => true}});
  assert.equal(exitCode, 0);
  assert.deepEqual(configCalls,
                   ["dbPath", "myWxid", "decryptKey", "wxidConfigs"]);
  assert.deepEqual(calls[0],
    {name: "setPaths", args: [workerResources, boot.userDataDir]});
  assert.deepEqual(calls.find(call => call.name === "testConnection").args,
                   [path.dirname(dbStorageDir), syntheticHexKey]);
  const encoded = fs.readFileSync(boot.resultPath, "utf8");
  const result = JSON.parse(encoded);
  assert.equal(result.status, "ok");
  assert.equal(result.gates.nativeProtectionAuthenticated, true);
  assert.equal(result.validation.databaseCount, 2);
  assert.equal(encoded.includes(syntheticHexKey), false);
  assert.equal(encoded.toLowerCase().includes(syntheticHexKey.toLowerCase()),
               false);
});

test("presentation validation opens db_storage under presentation dbPath",
     async t => {
  const fixture = bootFixture(t, {names: {area: "presentation"}});
  fs.writeFileSync(fixture.requestPath, JSON.stringify({
    operation: "validate-snapshot", runId: RUN_ID, area: "presentation"
  }));
  const workerResources = path.join(fixture.resourcesPath, "resources");
  fs.mkdirSync(workerResources);
  const boot = _prepareBootForTest({
    app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request", fixture.requestPath],
    env: fixture.env,
    resourcesPath: fixture.resourcesPath
  }, fixture.snapshotsRoot);
  const sourceAccountName = "wxid_test";
  const roleRoot = path.join(boot.runRoot, "presentation");
  const accountRoot = path.join(roleRoot, sourceAccountName);
  const dbStorageDir = path.join(accountRoot, "db_storage");
  const message = path.join(dbStorageDir, "message", "message_0.db");
  const media = path.join(dbStorageDir, "media", "media_0.db");
  fs.mkdirSync(path.dirname(message), {recursive: true});
  fs.mkdirSync(path.dirname(media), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "attach"), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"));
  fs.writeFileSync(message, "synthetic-message");
  fs.writeFileSync(media, "synthetic-media");
  const syntheticHexKey = "AB".repeat(32);
  const values = {
    dbPath: roleRoot,
    myWxid: sourceAccountName,
    decryptKey: syntheticHexKey,
    wxidConfigs: {
      [sourceAccountName]: {decryptKey: syntheticHexKey.toLowerCase()}
    }
  };
  class ConfigService {
    async get(name) {
      return values[name];
    }
  }
  const calls = [];
  const service = fakeService(calls, {
    resourcesPath: workerResources,
    userDataDir: boot.userDataDir,
    dbStorageDir,
    sourceAccountName,
    syntheticHexKey
  });

  const exitCode = await _runValidatorForTest({
    boot,
    ConfigService,
    wcdbService: service,
    resourcesPath: workerResources,
    app: fixture.app
  }, {safeStorage: {isEncryptionAvailable: () => true}});

  assert.equal(exitCode, 0);
  assert.deepEqual(
    calls.find(call => call.name === "testConnection").args,
    [path.dirname(dbStorageDir), syntheticHexKey]
  );
});

test("avatar aggregate operation publishes counts only in the main result",
     async t => {
  const fixture = bootFixture(t);
  fs.writeFileSync(fixture.requestPath, JSON.stringify({
    operation: "avatar-aggregate",
    runId: RUN_ID,
    area: "validation"
  }));
  const workerResources = path.join(fixture.resourcesPath, "resources");
  fs.mkdirSync(workerResources);
  const boot = _prepareBootForTest({
    app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request", fixture.requestPath],
    env: fixture.env,
    resourcesPath: fixture.resourcesPath
  }, fixture.snapshotsRoot);
  const sourceAccountName = "wxid_synthetic_account";
  const roleRoot = path.join(boot.runRoot, "validation");
  const dbStorageDir = path.join(
    roleRoot, sourceAccountName, "db_storage");
  fs.mkdirSync(dbStorageDir, {recursive: true});
  const syntheticHexKey = "AB".repeat(32);
  const values = {
    dbPath: roleRoot,
    myWxid: sourceAccountName,
    decryptKey: syntheticHexKey,
    wxidConfigs: {
      [sourceAccountName]: {decryptKey: syntheticHexKey.toLowerCase()}
    }
  };
  class ConfigService {
    async get(name) {
      return values[name];
    }
  }
  const calls = [];
  const request = {
    resourcesPath: workerResources,
    userDataDir: boot.userDataDir,
    dbStorageDir,
    sourceAccountName,
    syntheticHexKey
  };
  const service = fakeService(calls, request);
  const identifiers = [
    "synthetic-contact-url",
    "synthetic-contact-buffer",
    "synthetic-contact-missing"
  ];
  service.getContactsCompact = async (...args) => {
    calls.push({name: "getContactsCompact", args});
    return {
      success: true,
      contacts: identifiers.map(username => ({
        username,
        nick_name: "forbidden-nickname",
        source_path: String.raw`X:\forbidden\avatar`
      }))
    };
  };
  service.getAvatarUrls = async (...args) => {
    calls.push({name: "getAvatarUrls", args});
    return {
      success: true,
      map: {
        [identifiers[0]]: "https://example.invalid/avatar"
      }
    };
  };
  service.getHeadImageBuffers = async (...args) => {
    calls.push({name: "getHeadImageBuffers", args});
    return {
      success: true,
      map: {
        [identifiers[1]]: "FFD8FFE0"
      }
    };
  };

  const exitCode = await _runValidatorForTest({
    boot,
    ConfigService,
    wcdbService: service,
    resourcesPath: workerResources,
    app: fixture.app
  }, {safeStorage: {isEncryptionAvailable: () => true}});

  assert.equal(exitCode, 0);
  const resultEncoded = fs.readFileSync(boot.resultPath, "utf8");
  const avatarAggregate = {
    version: 1,
    candidateContactCount: 3,
    avatarUrlCount: 1,
    headImageBufferCount: 1,
    finalAvatarCount: 2,
    missingAvatarCount: 1,
    reasonCounts: {
      urlOnly: 1,
      headImageBufferOnly: 1,
      urlAndHeadImageBuffer: 0,
      noSupportedSource: 1
    }
  };
  assert.deepEqual(JSON.parse(resultEncoded), {
    version: 1,
    runId: RUN_ID,
    operation: "avatar-aggregate",
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
    validation: avatarAggregate,
    callsBeforeOpen: ["setPaths", "testConnection"]
  });
  assert.equal(fs.existsSync(path.join(
    path.dirname(boot.resultPath), "avatar-aggregate.json")), false);
  const stageEncoded = fs.readFileSync(
    path.join(boot.userDataDir, "validator-stage.log"), "utf8");
  const publicOutput = resultEncoded + stageEncoded;
  for (const forbidden of [
    ...identifiers,
    sourceAccountName,
    syntheticHexKey,
    "forbidden-nickname",
    "example.invalid",
    "FFD8FFE0",
    String.raw`X:\forbidden`
  ]) {
    assert.equal(publicOutput.includes(forbidden), false);
  }
});

test("media openability operation publishes counts only in the main result",
     async t => {
  const fixture = bootFixture(t, {names: {area: "presentation"}});
  fs.writeFileSync(fixture.requestPath, JSON.stringify({
    operation: "media-openability",
    runId: RUN_ID,
    area: "presentation"
  }));
  const workerResources = path.join(fixture.resourcesPath, "resources");
  fs.mkdirSync(workerResources);
  const boot = _prepareBootForTest({
    app: fixture.app,
    argv: ["WeFlow.exe", "--weflow-validator-request", fixture.requestPath],
    env: fixture.env,
    resourcesPath: fixture.resourcesPath
  }, fixture.snapshotsRoot);
  const sourceAccountName = "wxid_synthetic_account";
  const roleRoot = path.join(boot.runRoot, "presentation");
  const accountRoot = path.join(roleRoot, sourceAccountName);
  const dbStorageDir = path.join(accountRoot, "db_storage");
  const imagePath = path.join(
    accountRoot, "msg", "attach", "synthetic", "image.dat");
  fs.mkdirSync(dbStorageDir, {recursive: true});
  fs.mkdirSync(path.dirname(imagePath), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  fs.writeFileSync(imagePath, Buffer.from("FFD8FFE000104A46", "hex"));
  const syntheticHexKey = "AB".repeat(32);
  const values = {
    dbPath: roleRoot,
    myWxid: sourceAccountName,
    decryptKey: syntheticHexKey,
    imageXorKey: 0x5A,
    imageAesKey: "0123456789abcdef",
    wxidConfigs: {
      [sourceAccountName]: {decryptKey: syntheticHexKey.toLowerCase()}
    }
  };
  class ConfigService {
    async get(name) {
      return values[name];
    }
  }
  const calls = [];
  const request = {
    resourcesPath: workerResources,
    userDataDir: boot.userDataDir,
    dbStorageDir,
    sourceAccountName,
    syntheticHexKey
  };
  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "forbidden-session",
      localId: 31,
      localType: 3,
      createTime: 300,
      mediaType: "image",
      imageMd5: "a".repeat(32),
      imageDatName: "forbidden-image"
    }],
    hasMore: false,
    nextOffset: 1
  });
  service.resolveImageHardlink = async () => ({
    success: true,
    data: {file_name: path.basename(imagePath), full_path: imagePath}
  });

  const exitCode = await _runValidatorForTest({
    boot,
    ConfigService,
    wcdbService: service,
    resourcesPath: workerResources,
    app: fixture.app
  }, {safeStorage: {isEncryptionAvailable: () => true}});

  assert.equal(exitCode, 0);
  const encoded = fs.readFileSync(boot.resultPath, "utf8");
  const result = JSON.parse(encoded);
  assert.equal(result.operation, "media-openability");
  assert.deepEqual(result.validation, {
    version: 1,
    candidateCount: 1,
    imageCandidateCount: 1,
    videoCandidateCount: 0,
    locallyUnavailableCount: 0,
    localFileCount: 1,
    readableImageCount: 1,
    readableVideoCount: 0,
    unreadableLocalCount: 0
  });
  for (const forbidden of [
    sourceAccountName,
    syntheticHexKey,
    "0123456789abcdef",
    "forbidden-session",
    "forbidden-image",
    imagePath
  ]) {
    assert.equal(encoded.includes(forbidden), false);
  }
});

test("validation sets copied resources and isolated userData first", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const service = fakeService(calls, request);
  await runSnapshotGateway(service, request);
  assert.deepEqual(calls.slice(0, 4).map(call => call.name),
                   ["setPaths", "testConnection", "open", "getSessions"]);
  assert.deepEqual(calls[0].args,
                   [request.resourcesPath, request.userDataDir]);
});

test("validation uses the decrypted current-account key without emitting it",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const service = fakeService(calls, request);
  const result = await runSnapshotGateway(service, request);
  assert.equal(result.status, "ok");
  assert.equal(JSON.stringify(result).includes(request.syntheticHexKey), false);
  assert.equal(calls.find(call => call.name === "testConnection")
                    .args[0], path.dirname(request.dbStorageDir));
  assert.equal(calls.find(call => call.name === "open")
                    .args[0], path.dirname(request.dbStorageDir));
  assert.equal(calls.find(call => call.name === "testConnection")
                    .args[1], request.syntheticHexKey);
});

test("open failure never claims native authentication", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const service = fakeService(calls, request);
  service.open = async (...args) => {
    calls.push({name: "open", args}); return false;
  };
  const result = await runSnapshotGateway(service, request);
  assert.equal(result.status, "compatibility_blocked");
  assert.equal(result.reasonCode, "open_failed");
  assert.equal(result.nativeProtectionAuthenticated, false);
  assert.equal(result.workerSetPathsCalled, true);
});

test("raw worker and arbitrary query are unreachable", () => {
  assert.equal("callWorker" in exportedGateway(), false);
  assert.throws(() => assertAllowedWorkerMethod("execQuery"));
});

test("gateway uses the fixed 6.1 service wrapper ABI", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const service = fakeService(calls, request);
  await runSnapshotGateway(service, request);
  assert.deepEqual(calls.find(call => call.name === "getMessageTableStats").args,
                   ["synthetic-session"]);
  const list = calls.find(call => call.name === "listTables" &&
                                 call.args[0] === "message");
  assert.deepEqual(list.args,
    ["message", path.join(request.dbStorageDir, "message", "message_0.db")]);
  assert.deepEqual(calls.find(call => call.name === "getTableSchema" &&
                                    call.args[0] === "message").args,
    ["message", list.args[1], "message"]);
});

for (const mode of ["missing", "extra", "no-match", "duplicate"]) {
  test(`message stats ${mode} keys block instead of becoming null`, async t => {
    const calls = [];
    const request = fakeRequest(t);
    const service = fakeService(calls, request);
    if (mode === "missing") {
      service.getAggregateStats = async (...args) => {
        calls.push({name: "getAggregateStats", args});
        return {success: true, data: {total: 1, sessions: {}}};
      };
    }
    service.getMessageTableStats = async (...args) => {
      calls.push({name: "getMessageTableStats", args});
      const matching = {
        db_path: path.join(request.dbStorageDir,
                           "message", "message_0.db"),
        table_name: mode === "no-match" ? "other" : "message", count: 0
      };
      if (mode === "missing") return {success: true, tables: []};
      if (mode === "duplicate") {
        return {success: true, tables: [matching, {...matching}]};
      }
      if (mode === "extra") return {success: true, tables: [matching, {
        db_path: path.join(request.dbStorageDir, "media", "media_0.db"),
        table_name: "extra", count: 0
      }]};
      return {success: true, tables: [matching]};
    };
    await assert.rejects(runSnapshotGateway(service, request),
                         /worker_contract_mismatch/);
  });
}

test("an on-disk database omitted by the fixed classifiers blocks", async t => {
  const calls = [];
  const request = fakeRequest(t);
  fs.writeFileSync(path.join(request.dbStorageDir, "unknown.db"), "unknown");
  await assert.rejects(
    runSnapshotGateway(fakeService(calls, request), request),
    /worker_database_unclassified/);
});
