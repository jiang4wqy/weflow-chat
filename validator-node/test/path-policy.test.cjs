const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {deriveAreaLayout} = require("../src/path-policy.cjs");
const {
  createJunctionFixture,
  createRoleFixture
} = require("./helpers.cjs");

function createPresentationFixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "wf-presentation-"));
  const runRoot = path.join(base, "run");
  const roleRoot = path.join(runRoot, "presentation");
  const accountRoot = path.join(roleRoot, "wxid_test");
  const dbStorage = path.join(accountRoot, "db_storage");
  const msg = path.join(accountRoot, "msg");
  fs.mkdirSync(dbStorage, {recursive: true});
  fs.mkdirSync(path.join(msg, "attach"), {recursive: true});
  fs.mkdirSync(path.join(msg, "video"));
  t.after(() => fs.rmSync(base, {recursive: true, force: true}));
  return {
    runRoot,
    roleRoot,
    accountRoot,
    dbStorage,
    msg,
    sourceAccountName: "wxid_test"
  };
}

test("source is never an allowed area", () => {
  assert.throws(() => deriveAreaLayout({
    runRoot: "E:\\run",
    area: "source",
    sourceAccountName: "wxid_test"
  }), /request_area_rejected/);
});

test("every unsupported area is rejected", () => {
  assert.throws(() => deriveAreaLayout({
    runRoot: "E:\\run",
    area: "unsupported",
    sourceAccountName: "wxid_test"
  }), /request_area_rejected/);
});

test("account directory traversal and sibling-prefix escape are rejected", () => {
  for (const sourceAccountName of [
    "..\\escape",
    "wxid_test:stream",
    "wxid_bad-name",
    "wxid_",
    `wxid_${"a".repeat(129)}`,
    "E:\\run-evil\\wxid_test"
  ]) {
    assert.throws(() => deriveAreaLayout({
      runRoot: "E:\\run",
      area: "validation",
      sourceAccountName
    }), /request_path_rejected/);
  }
});

test("account layout is role/direct-account/db_storage", t => {
  const fixture = createRoleFixture(t);
  const layout = deriveAreaLayout({
    runRoot: fixture.runRoot,
    area: "validation",
    sourceAccountName: fixture.sourceAccountName
  });
  assert.equal(layout.roleRoot, fixture.roleRoot);
  assert.equal(layout.accountRoot, fixture.accountRoot);
  assert.equal(layout.dbStorage, fixture.dbStorage);
});

test("active keeps the existing db_storage-only account contract", t => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "wf-active-"));
  t.after(() => fs.rmSync(base, {recursive: true, force: true}));
  const runRoot = path.join(base, "run");
  const accountRoot = path.join(runRoot, "active", "wxid_test");
  fs.mkdirSync(path.join(accountRoot, "db_storage"), {recursive: true});
  assert.doesNotThrow(() => deriveAreaLayout({
    runRoot,
    area: "active",
    sourceAccountName: "wxid_test"
  }));
  fs.mkdirSync(path.join(accountRoot, "msg"));
  assert.throws(() => deriveAreaLayout({
    runRoot,
    area: "active",
    sourceAccountName: "wxid_test"
  }), /request_account_layout_rejected/);
});

test("presentation layout is account/db_storage plus msg/attach and video",
     t => {
  const fixture = createPresentationFixture(t);
  const layout = deriveAreaLayout({
    runRoot: fixture.runRoot,
    area: "presentation",
    sourceAccountName: fixture.sourceAccountName
  });
  assert.equal(layout.roleRoot, fixture.roleRoot);
  assert.equal(layout.accountRoot, fixture.accountRoot);
  assert.equal(layout.dbStorage, fixture.dbStorage);
});

for (const scope of ["role", "account", "msg"]) {
  test(`presentation rejects an unexpected ${scope} entry`, t => {
    const fixture = createPresentationFixture(t);
    const parent = {
      role: fixture.roleRoot,
      account: fixture.accountRoot,
      msg: fixture.msg
    }[scope];
    fs.writeFileSync(path.join(parent, "unexpected"), "sentinel");
    assert.throws(() => deriveAreaLayout({
      runRoot: fixture.runRoot,
      area: "presentation",
      sourceAccountName: fixture.sourceAccountName
    }), /request_account_layout_rejected/);
  });
}

test("presentation rejects a non-directory media root", t => {
  const fixture = createPresentationFixture(t);
  const attach = path.join(fixture.msg, "attach");
  fs.rmSync(attach, {recursive: true});
  fs.writeFileSync(attach, "not-a-directory");
  assert.throws(() => deriveAreaLayout({
    runRoot: fixture.runRoot,
    area: "presentation",
    sourceAccountName: fixture.sourceAccountName
  }), /request_account_layout_rejected/);
});

test("presentation rejects a reparse media root", t => {
  const fixture = createPresentationFixture(t);
  const attach = path.join(fixture.msg, "attach");
  const outside = path.join(path.dirname(fixture.runRoot), "outside");
  fs.rmSync(attach, {recursive: true});
  fs.mkdirSync(outside);
  try {
    fs.symlinkSync(outside, attach, "junction");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
      t.skip("junction creation unavailable");
      return;
    }
    throw error;
  }
  assert.throws(() => deriveAreaLayout({
    runRoot: fixture.runRoot,
    area: "presentation",
    sourceAccountName: fixture.sourceAccountName
  }), /request_reparse_rejected/);
});

test("a reparse component under the run root is rejected", t => {
  const fixture = createJunctionFixture(t);
  assert.throws(() => deriveAreaLayout({
    runRoot: fixture.runRoot,
    area: "validation",
    sourceAccountName: fixture.sourceAccountName
  }), /request_reparse_rejected/);
});
