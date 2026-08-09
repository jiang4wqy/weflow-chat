// validator-node/src/path-policy.cjs
const fs = require("node:fs");
const path = require("node:path");

function inside(child, root) {
  const relative = path.relative(root, child);
  return relative !== "" && !relative.startsWith(".." + path.sep) &&
         relative !== ".." && !path.isAbsolute(relative);
}

function rejectReparseChain(root, target) {
  let current = root;
  const relative = path.relative(root, target);
  for (const part of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) continue;
    const info = fs.lstatSync(current);
    if (info.isSymbolicLink()) throw new Error("request_reparse_rejected");
  }
}

exports.deriveAreaLayout = function ({runRoot, area, sourceAccountName}) {
  if (!new Set(["validation", "active", "presentation"]).has(area)) {
    throw new Error("request_area_rejected");
  }
  if (typeof sourceAccountName !== "string" ||
      !/^wxid_[A-Za-z0-9_]{1,128}$/.test(sourceAccountName) ||
      sourceAccountName.includes(":")) {
    throw new Error("request_path_rejected");
  }
  const root = fs.realpathSync.native(path.resolve(runRoot));
  const roleRoot = path.resolve(root, area);
  const accountRoot = path.resolve(roleRoot, sourceAccountName);
  const dbStorage = path.resolve(accountRoot, "db_storage");
  if (!inside(roleRoot, root) || path.dirname(accountRoot) !== roleRoot ||
      path.dirname(dbStorage) !== accountRoot) {
    throw new Error("request_path_rejected");
  }
  rejectReparseChain(root, dbStorage);
  if (!fs.existsSync(dbStorage) || !fs.statSync(dbStorage).isDirectory() ||
      fs.readdirSync(roleRoot).join("\0") !== sourceAccountName) {
    throw new Error("request_account_layout_rejected");
  }
  if (area === "presentation") {
    const msg = path.resolve(accountRoot, "msg");
    const attach = path.resolve(msg, "attach");
    const video = path.resolve(msg, "video");
    if (path.dirname(msg) !== accountRoot ||
        path.dirname(attach) !== msg || path.dirname(video) !== msg) {
      throw new Error("request_path_rejected");
    }
    for (const directory of [msg, attach, video]) {
      rejectReparseChain(root, directory);
    }
    if (fs.readdirSync(accountRoot).sort().join("\0") !==
        ["db_storage", "msg"].join("\0") ||
        !fs.existsSync(msg) || !fs.lstatSync(msg).isDirectory() ||
        !fs.existsSync(attach) || !fs.lstatSync(attach).isDirectory() ||
        !fs.existsSync(video) || !fs.lstatSync(video).isDirectory() ||
        fs.readdirSync(msg).sort().join("\0") !==
        ["attach", "video"].join("\0")) {
      throw new Error("request_account_layout_rejected");
    }
  } else if (fs.readdirSync(accountRoot).join("\0") !== "db_storage") {
    throw new Error("request_account_layout_rejected");
  }
  const resolved = fs.realpathSync.native(dbStorage);
  if (!inside(resolved, root)) throw new Error("request_path_rejected");
  return {roleRoot, accountRoot, dbStorage};
};
