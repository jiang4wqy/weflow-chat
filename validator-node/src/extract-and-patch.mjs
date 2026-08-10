import * as asar from "@electron/asar";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {assertMainContract, patchMain} from "./main-patch.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNTIME = Object.freeze({
  "WeFlow.exe": "5E9007F1FCE332C4038628FB2EAE0518FC6DCA252041A1563B0AD60292FA6A13",
  "resources/app.asar": "F27D53EA61E97365865D999AC7EB03149BDAB670BFEF6851964190CEE5F33E80",
  "resources/resources/wcdb/win32/x64/wcdb_api.dll":
    "5D5DFFE151F6CF7C1122D34FB6C6F5E902685547CFED83891EDF8C23B78907B2",
  "resources/resources/wcdb/win32/x64/WCDB.dll":
    "DE80DC7B9117076F7F77E5AB5D6EE8DC44F8D3829C10549A800AF2E4E219EBF8"
});
const EXTRACTED = Object.freeze({
  "dist-electron/main.js":
    "1ABB5B41D039AA84FD43D734C1213F47815616141A30C99DA92BB183F803AADD",
  "dist-electron/config-C9Ue62at.js":
    "77F636C0E8C39E10C774E80ECC1AEA5503BAA8BB6E853D16108D2D182D9B6045",
  "dist-electron/wcdbWorker.js":
    "C53892300A724D60CA5C733316332C47E20E41465B5396F764C0BE265C576890"
});
const PATCHED_MAIN_SHA256 =
  "51B9B75A1A1E575381692AD36988F97C0690E4BFFC8554443AA1DF3554D835C8";
const COPIED_MODULES = Object.freeze({
  "validator-entry.cjs":
    "2800CF8946B2C8846EBE8F29938C822C8CB96D092D19B8F6303BDE4878720CC3",
  "path-policy.cjs":
    "3A864F017A36E73743E3045BDB68313DD7C67BC9274B1EBF9C47F800250CFA6F",
  "worker-gateway.cjs":
    "109E9C4D29124947BCC6DF124710FE9D70F28C6543FB81B1D60F63FCE42AFEBE",
  "avatar-aggregate.cjs":
    "4515698E4B431F7BF93539D9885C6E3FDE126C53DE71528A86053FE9B3E1E31B",
  "aggregate.cjs":
    "E4DF825B52B07EF06A02FF49E2D4947F7AA7685C0EAC794528EB9EA9A59288D9",
  "sanitize-result.cjs":
    "B8590A81C10FDF6C16AE556E56608214958D6A73AE71A3562CC959646172C67C"
});

const sha256File = target => crypto.createHash("sha256")
  .update(fs.readFileSync(target)).digest("hex").toUpperCase();
const resolveRelative = (root, relative) =>
  path.join(root, ...relative.split("/"));

function verifyContract(root, contract) {
  const hashes = {};
  for (const [relative, expected] of Object.entries(contract)) {
    const target = resolveRelative(root, relative);
    if (!fs.existsSync(target) || sha256File(target) !== expected) {
      throw new Error("compatibility_blocked");
    }
    hashes[relative] = expected;
  }
  return hashes;
}

export const _verifyContractForTest = verifyContract;
export const _copiedModuleContractForTest = () =>
  Object.freeze({...COPIED_MODULES});
export const verifyRuntimeContract = root => verifyContract(root, RUNTIME);
export const verifyExtractedContract = root => verifyContract(root, EXTRACTED);

function extractArchive(archive, vendor, staging) {
  asar.extractAll(archive, staging);
  fs.renameSync(archive, vendor);
}

export const _extractArchiveForTest = extractArchive;

export function patchCopiedRuntime(runtimeRoot) {
  const root = fs.realpathSync.native(path.resolve(runtimeRoot));
  const resources = path.join(root, "resources");
  const archive = path.join(resources, "app.asar");
  const vendor = path.join(resources, "app.vendor.asar");
  const staging = path.join(resources, "app.staging");
  const app = path.join(resources, "app");
  if (fs.existsSync(vendor) || fs.existsSync(staging) || fs.existsSync(app)) {
    throw new Error("compatibility_blocked");
  }
  const runtimeHashes = verifyRuntimeContract(root);
  try {
    extractArchive(archive, vendor, staging);
    const extractedHashes = verifyExtractedContract(staging);
    const mainPath = path.join(staging, "dist-electron", "main.js");
    const original = fs.readFileSync(mainPath, "utf8");
    const anchors = assertMainContract(original);
    fs.writeFileSync(mainPath, patchMain(original), "utf8");
    if (sha256File(mainPath) !== PATCHED_MAIN_SHA256) {
      throw new Error("compatibility_blocked");
    }
    const copiedModuleHashes = {};
    for (const [name, expected] of Object.entries(COPIED_MODULES)) {
      const source = path.join(HERE, name);
      if (sha256File(source) !== expected) {
        throw new Error("compatibility_blocked");
      }
      const destination = path.join(staging, "dist-electron", name);
      fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
      if (sha256File(destination) !== expected) {
        throw new Error("compatibility_blocked");
      }
      copiedModuleHashes[`dist-electron/${name}`] = expected;
    }
    const manifest = {
      version: 1,
      runtimeHashes,
      extractedHashes,
      copiedModuleHashes,
      anchors,
      patchedMainSha256: sha256File(mainPath),
      vendorAsarSha256: sha256File(vendor)
    };
    fs.writeFileSync(
      path.join(staging, "validator-patch.json"),
      JSON.stringify(manifest),
      {encoding: "utf8", flag: "wx"}
    );
    fs.renameSync(staging, app);
    return manifest;
  } catch (error) {
    fs.rmSync(staging, {recursive: true, force: true});
    if (!fs.existsSync(archive) && fs.existsSync(vendor)) {
      fs.renameSync(vendor, archive);
    }
    throw error;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4 || process.argv[2] !== "--runtime-root") {
    throw new Error("cli_arguments_rejected");
  }
  process.stdout.write(JSON.stringify(patchCopiedRuntime(process.argv[3])));
}
