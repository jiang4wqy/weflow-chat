import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import {_verifyContractForTest} from "../src/extract-and-patch.mjs";

const NAMES = new Map([
  ["WeFlow.exe", "WeFlow.exe"], ["app.asar", "resources/app.asar"],
  ["main.js", "resources/app/dist-electron/main.js"],
  ["config-C9Ue62at.js", "resources/app/dist-electron/config-C9Ue62at.js"],
  ["wcdbWorker.js", "resources/app/dist-electron/wcdbWorker.js"],
  ["wcdb_api.dll", "resources/resources/wcdb/win32/x64/wcdb_api.dll"],
  ["WCDB.dll", "resources/resources/wcdb/win32/x64/WCDB.dll"]
]);

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex")
    .toUpperCase();
}

export function syntheticMain() {
  return "var z=new rn;" +
    "var RQ=null,zQ=r.app.requestSingleInstanceLock();" +
    "r.app.whenReady().then(async()=>{if(!zQ)return;kX=new e.t" +
    ";ordinaryBackground();});";
}

export async function executePatchedMain(source, {
  enabled,
  shutdown = null,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout
}) {
  const events = [];
  let completion;
  class WcdbService {
    constructor() { events.push("wcdb"); }
    async shutdown() {
      events.push("shutdown");
      if (shutdown) {
        await shutdown();
        events.push("shutdown:done");
      }
    }
  }
  class ConfigService { constructor() { events.push("config"); } }
  const validator = {
    prepareBoot() { events.push("prepareBoot"); return {enabled}; },
    async runValidator({wcdbService}) {
      assert.equal(wcdbService instanceof WcdbService, true);
      events.push("validator");
      return 0;
    },
    writeEarlyFailure() {}
  };
  const app = {
    requestSingleInstanceLock() { events.push("lock"); return true; },
    whenReady() { return {then(callback) {
      completion = Promise.resolve().then(callback); return completion;
    }}; },
    exit(code) { events.push(`exit:${code}`); },
    quit() { events.push("quit"); }
  };
  vm.runInNewContext(source, {
    require(name) {
      assert.equal(name, "./validator-entry.cjs"); return validator;
    },
    r: {app}, e: {t: ConfigService}, rn: WcdbService,
    t: {join: path.join},
    process: {argv: [], env: {}, resourcesPath: "R:\\copied\\resources"},
    setTimeout: setTimeoutFn,
    clearTimeout: clearTimeoutFn,
    ordinaryBackground() { events.push("ui"); }
  });
  await completion;
  return events;
}

function corruptFile(target) {
  fs.appendFileSync(target, Buffer.from([0x00]));
}

export async function copyAndPatchFixture({corrupt}) {
  if (!NAMES.has(corrupt)) {
    throw new Error("unknown_contract_artifact");
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wf-runtime-"));
  try {
    for (const [name, relative] of NAMES) {
      const destination = path.join(root, ...relative.split("/"));
      fs.mkdirSync(path.dirname(destination), {recursive: true});
      fs.writeFileSync(destination,
        name === "main.js" ? syntheticMain() : `synthetic-${name}`);
    }
    const contract = Object.fromEntries([...NAMES.values()].map(relative => {
      const target = path.join(root, ...relative.split("/"));
      return [relative, sha256(fs.readFileSync(target))];
    }));
    corruptFile(path.join(root, ...NAMES.get(corrupt).split("/")));
    return _verifyContractForTest(root, contract);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
}
