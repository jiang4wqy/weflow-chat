const AGGREGATE_KEYS = new Set([
  "version",
  "candidateContactCount",
  "avatarUrlCount",
  "headImageBufferCount",
  "finalAvatarCount",
  "missingAvatarCount",
  "reasonCounts",
]);
const REASON_KEYS = new Set([
  "urlOnly",
  "headImageBufferOnly",
  "urlAndHeadImageBuffer",
  "noSupportedSource",
]);
const CONTACT_KEYS = new Set([
  "hasAvatarUrl",
  "hasHeadImageBuffer",
]);
const exact = (value, keys) => {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) return false;
  const names = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return names.length === keys.size &&
    names.every(name => typeof name === "string" && keys.has(name) &&
      Object.hasOwn(descriptors[name], "value") &&
      descriptors[name].enumerable);
};
const nonnegativeSafeInteger = value =>
  Number.isSafeInteger(value) && value >= 0;

exports.aggregateAvatarCoverage = function (contacts) {
  if (!Array.isArray(contacts) || Array.from(contacts).some(contact =>
    !exact(contact, CONTACT_KEYS) ||
    typeof contact.hasAvatarUrl !== "boolean" ||
    typeof contact.hasHeadImageBuffer !== "boolean")) {
    throw new Error("avatar_aggregate_input_invalid");
  }
  const reasonCounts = {
    urlOnly: 0,
    headImageBufferOnly: 0,
    urlAndHeadImageBuffer: 0,
    noSupportedSource: 0,
  };
  for (const contact of contacts) {
    if (contact.hasAvatarUrl && contact.hasHeadImageBuffer) {
      reasonCounts.urlAndHeadImageBuffer += 1;
    } else if (contact.hasAvatarUrl) {
      reasonCounts.urlOnly += 1;
    } else if (contact.hasHeadImageBuffer) {
      reasonCounts.headImageBufferOnly += 1;
    } else {
      reasonCounts.noSupportedSource += 1;
    }
  }
  return {
    version: 1,
    candidateContactCount: contacts.length,
    avatarUrlCount: reasonCounts.urlOnly +
      reasonCounts.urlAndHeadImageBuffer,
    headImageBufferCount: reasonCounts.headImageBufferOnly +
      reasonCounts.urlAndHeadImageBuffer,
    finalAvatarCount: contacts.length - reasonCounts.noSupportedSource,
    missingAvatarCount: reasonCounts.noSupportedSource,
    reasonCounts,
  };
};

exports.sanitizeAvatarAggregate = function (value) {
  if (!exact(value, AGGREGATE_KEYS) ||
      !exact(value.reasonCounts, REASON_KEYS) ||
      value.version !== 1 ||
      ![
        "candidateContactCount",
        "avatarUrlCount",
        "headImageBufferCount",
        "finalAvatarCount",
        "missingAvatarCount",
      ].every(name => nonnegativeSafeInteger(value[name])) ||
      !Object.values(value.reasonCounts).every(nonnegativeSafeInteger)) {
    throw new Error("avatar_aggregate_schema_mismatch");
  }
  const {
    urlOnly,
    headImageBufferOnly,
    urlAndHeadImageBuffer,
    noSupportedSource,
  } = value.reasonCounts;
  const expected = {
    candidateContactCount: urlOnly + headImageBufferOnly +
      urlAndHeadImageBuffer + noSupportedSource,
    avatarUrlCount: urlOnly + urlAndHeadImageBuffer,
    headImageBufferCount: headImageBufferOnly + urlAndHeadImageBuffer,
    finalAvatarCount: urlOnly + headImageBufferOnly +
      urlAndHeadImageBuffer,
    missingAvatarCount: noSupportedSource,
  };
  if (!Object.values(expected).every(nonnegativeSafeInteger) ||
      !Object.entries(expected).every(
        ([name, count]) => value[name] === count)) {
    throw new Error("avatar_aggregate_count_mismatch");
  }
  return JSON.parse(JSON.stringify(value));
};
