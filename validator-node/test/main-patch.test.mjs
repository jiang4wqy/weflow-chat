import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {fileURLToPath} from "node:url";
import * as asar from "@electron/asar";
import {patchMain, assertMainContract} from "../src/main-patch.mjs";
import {
  syntheticMain, sha256, copyAndPatchFixture, executePatchedMain
} from "./fixtures.mjs";

test("requires exactly one boot and one ready anchor", () => {
  assert.throws(() => patchMain("var noMatch=1;"),
                /main_anchor_mismatch/);
});

test("patches both anchors once", () => {
  const source =
    "var z=new rn;var RQ=null,zQ=r.app.requestSingleInstanceLock();" +
    "r.app.whenReady().then(async()=>{if(!zQ)return;kX=new e.t;";
  const output = patchMain(source);
  assert.equal((output.match(/__wfValidator/g) || []).length > 1, true);
  assert.equal((output.match(/requestSingleInstanceLock/g) || []).length, 1);
});

test("the synthetic main has the exact semantic anchors", () => {
  const source = syntheticMain();
  assert.deepEqual(assertMainContract(source), {
    bootAnchorCount: 1,
    readyAnchorCount: 1,
    configConstructorCount: 1,
    wcdbSingletonCount: 1
  });
});

test("the synthetic patched main has exact bytes", () => {
  const output = patchMain(syntheticMain());
  assert.equal(Buffer.byteLength(output), 1049);
  assert.equal(sha256(output),
    "B232F0C85AAE2275CC124106A0BA092251710991CCD37BF008CB4173C9E63AFF");
});

test("validator receives the already-constructed fixed singleton", async () => {
  const events = await executePatchedMain(
    patchMain(syntheticMain()), {enabled: true});
  assert.deepEqual(events, ["wcdb", "prepareBoot", "lock", "validator",
                            "shutdown", "exit:0"]);
  assert.equal(events.includes("ui"), false);
});

test("validator exit is bounded when WCDB shutdown never settles", async () => {
  let clearedTimer = null;
  const execution = executePatchedMain(
    patchMain(syntheticMain()), {
      enabled: true,
      shutdown: () => new Promise(() => {}),
      setTimeoutFn(callback, delay) {
        assert.equal(delay, 5000);
        queueMicrotask(callback);
        return 17;
      },
      clearTimeoutFn(timer) { clearedTimer = timer; }
    }
  );
  const outcome = await Promise.race([
    execution.then(events => ({status: "completed", events})),
    new Promise(resolve => setTimeout(
      () => resolve({status: "hung"}), 50))
  ]);
  assert.equal(outcome.status, "completed");
  assert.deepEqual(outcome.events,
    ["wcdb", "prepareBoot", "lock", "validator", "shutdown", "exit:0"]);
  assert.equal(clearedTimer, 17);
});

test("validator waits for a normal WCDB shutdown before exit", async () => {
  const events = await executePatchedMain(
    patchMain(syntheticMain()), {
      enabled: true,
      shutdown: () => Promise.resolve()
    }
  );
  assert.deepEqual(events, ["wcdb", "prepareBoot", "lock", "validator",
                            "shutdown", "shutdown:done", "exit:0"]);
});

test("ordinary launch still reaches normal startup", async () => {
  const events = await executePatchedMain(
    patchMain(syntheticMain()), {enabled: false});
  assert.deepEqual(events,
    ["wcdb", "prepareBoot", "lock", "config", "ui"]);
});

test("every repository copied module matches the current build contract",
     async () => {
  const patcher = await import("../src/extract-and-patch.mjs");
  const contract = patcher._copiedModuleContractForTest();
  assert.deepEqual(Object.keys(contract).sort(), [
    "aggregate.cjs", "avatar-aggregate.cjs", "path-policy.cjs",
    "sanitize-result.cjs", "validator-entry.cjs", "worker-gateway.cjs"]);
  for (const [name, expected] of Object.entries(contract)) {
    const raw = fs.readFileSync(path.join(
      path.dirname(fileURLToPath(import.meta.url)), "..", "src", name));
    assert.equal(sha256(raw), expected);
  }
});

test("each supplied synthetic contract hash mismatch blocks extraction",
     async () => {
  for (const artifact of ["WeFlow.exe", "app.asar", "main.js",
                          "config-C9Ue62at.js", "wcdbWorker.js",
                          "wcdb_api.dll", "WCDB.dll"]) {
    await assert.rejects(() => copyAndPatchFixture({corrupt: artifact}),
                         /compatibility_blocked/);
  }
});

test("extracts unpacked entries before preserving the vendor archive",
     async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-unpacked-"));
  try {
    const source = path.join(root, "source");
    const resources = path.join(root, "resources");
    const archive = path.join(resources, "app.asar");
    const vendor = path.join(resources, "app.vendor.asar");
    const staging = path.join(resources, "app.staging");
    fs.mkdirSync(path.join(source, "native"), {recursive: true});
    fs.mkdirSync(resources, {recursive: true});
    fs.writeFileSync(path.join(source, "main.js"), "ordinary");
    fs.writeFileSync(path.join(source, "native", "binding.node"),
                     "unpacked-native");
    await asar.createPackageWithOptions(source, archive, {
      unpack: "**/*.node"
    });
    const patcher = await import("../src/extract-and-patch.mjs");
    patcher._extractArchiveForTest(archive, vendor, staging);
    assert.equal(fs.existsSync(archive), false);
    assert.equal(fs.existsSync(vendor), true);
    assert.equal(fs.readFileSync(
      path.join(staging, "native", "binding.node"), "utf8"),
    "unpacked-native");
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test("installed 6.1 main is opt-in only",
     {skip: process.env.WEFLOW_RUN_HOST_CONTRACT !== "1" ||
       !process.env.WEFLOW_CHAT_HOST_ASAR}, async () => {
  const asar = await import("@electron/asar");
  const hostAsar = process.env.WEFLOW_CHAT_HOST_ASAR;
  const source = asar.extractFile(
    hostAsar,
    "dist-electron/main.js").toString("utf8");
  assert.equal(sha256(source),
    "1ABB5B41D039AA84FD43D734C1213F47815616141A30C99DA92BB183F803AADD");
  assert.equal(sha256(asar.extractFile(
    hostAsar,
    "dist-electron/config-C9Ue62at.js")),
    "77F636C0E8C39E10C774E80ECC1AEA5503BAA8BB6E853D16108D2D182D9B6045");
  assert.equal(sha256(asar.extractFile(
    hostAsar,
    "dist-electron/wcdbWorker.js")),
    "C53892300A724D60CA5C733316332C47E20E41465B5396F764C0BE265C576890");
  assertMainContract(source);
  const patched = patchMain(source);
  assert.equal(Buffer.byteLength(patched), 2532306);
  assert.equal(sha256(patched),
    "51B9B75A1A1E575381692AD36988F97C0690E4BFFC8554443AA1DF3554D835C8");
});
