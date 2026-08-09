// validator-node/src/aggregate.cjs
const crypto = require("node:crypto");
const path = require("node:path");

const digest = value => crypto.createHash("sha256")
  .update(JSON.stringify(value)).digest("hex").toUpperCase();

exports.aggregateValidation = function ({sourceAccountName, databases,
                                           nativeTotal}) {
  if (typeof sourceAccountName !== "string" || !Array.isArray(databases) ||
      !Number.isSafeInteger(nativeTotal) || nativeTotal < 0) {
    throw new Error("aggregate_input_invalid");
  }
  const accountHash = digest(sourceAccountName);
  const normalized = databases.map(database => {
    if (!database || typeof database.relativePath !== "string" ||
        path.win32.isAbsolute(database.relativePath) ||
        database.relativePath.split(/[\\/]/).includes("..") ||
        !["bizchat", "contact", "emoticon", "favorite", "general",
          "hardlink", "head_image", "media", "message", "migrate", "session",
          "sns", "solitaire"].includes(database.kind) ||
        !Array.isArray(database.tables)) {
      throw new Error("aggregate_database_invalid");
    }
    const tables = database.tables.map(table => ({
      nameHash: digest(String(table.name)),
      schemaHash: String(table.schemaHash).toUpperCase(),
      recordCount: table.recordCount === null ? null : Number(table.recordCount),
      minTimestamp: table.minTimestamp === null ? null : Number(table.minTimestamp),
      maxTimestamp: table.maxTimestamp === null ? null : Number(table.maxTimestamp),
    })).sort((left, right) => left.nameHash.localeCompare(right.nameHash));
    if (tables.some(table => !/^[0-9A-F]{64}$/.test(table.schemaHash) ||
          (table.recordCount !== null &&
           (!Number.isSafeInteger(table.recordCount) || table.recordCount < 0)) ||
          (table.minTimestamp !== null &&
           !Number.isSafeInteger(table.minTimestamp)) ||
          (table.maxTimestamp !== null &&
           !Number.isSafeInteger(table.maxTimestamp)))) {
      throw new Error("aggregate_table_invalid");
    }
    return {relativePath: database.relativePath.replaceAll("\\", "/"),
            kind: database.kind, tables};
  }).sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  const tableRows = normalized.flatMap(database => database.tables.map(table => ({
    accountHash, databaseKind: database.kind, ...table,
  })));
  const coverage = normalized.map(database => ({
    relativePath: database.relativePath, kind: database.kind,
  }));
  const recordCount = tableRows.reduce(
    (total, row) => total + (row.recordCount === null ? 0 : row.recordCount), 0);
  const timestamps = tableRows.flatMap(row =>
    [row.minTimestamp, row.maxTimestamp].filter(value => value !== null));
  return {
    databaseCount: normalized.length,
    tableCount: tableRows.length,
    recordCount,
    minTimestamp: timestamps.length ? Math.min(...timestamps) : null,
    maxTimestamp: timestamps.length ? Math.max(...timestamps) : null,
    schemaFingerprint: digest(tableRows.map(row =>
      ({accountHash: row.accountHash, databaseKind: row.databaseKind,
        nameHash: row.nameHash, schemaHash: row.schemaHash}))),
    aggregateFingerprint: digest({nativeTotal, tables: tableRows.map(row =>
      ({recordCount: row.recordCount, minTimestamp: row.minTimestamp,
        maxTimestamp: row.maxTimestamp}))}),
    databaseCoverageFingerprint: digest(coverage),
  };
};
