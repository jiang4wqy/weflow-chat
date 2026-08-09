const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  assertAllowedWorkerMethod,
  runAvatarAggregateGateway,
  runMediaOpenabilityGateway,
  runSnapshotGateway
} = require("../src/worker-gateway.cjs");
const {
  fakeRequest,
  fakeService
} = require("./helpers.cjs");

test("write-capable worker methods are rejected", () => {
  for (const name of [
    "execQuery",
    "importTableSnapshot",
    "updateMessage",
    "deleteMessage"
  ]) {
    assert.throws(
      () => assertAllowedWorkerMethod(name),
      /worker_method_rejected/
    );
  }
});

test("successful validation emits only fixed diagnostic stages", async t => {
  const calls = [];
  const stages = [];
  const request = {
    ...fakeRequest(t),
    markStage(stage) {
      stages.push(stage);
    }
  };

  const result = await runSnapshotGateway(
    fakeService(calls, request), request);

  assert.equal(result.status, "ok");
  assert.deepEqual(stages, [
    "gateway_started",
    "paths_set",
    "connection_tested",
    "account_opened",
    "sessions_loaded",
    "aggregate_loaded",
    "message_stats_loaded",
    "message_list_started",
    "message_list_loaded",
    "message_list_validated",
    "media_list_started",
    "media_list_loaded",
    "media_list_validated",
    "database_lists_loaded",
    "database_files_discovered",
    "tables_list_started",
    "tables_list_loaded",
    "table_schema_started",
    "table_schema_loaded",
    "database_scanned",
    "tables_list_started",
    "tables_list_loaded",
    "table_schema_started",
    "table_schema_loaded",
    "database_scanned",
    "fingerprints_ready"
  ]);
  assert.equal(stages.join("\n").includes(request.syntheticHexKey), false);
  assert.equal(stages.join("\n").includes(request.dbStorageDir), false);
});

test("avatar probe projects worker contact details before returning counts",
     async t => {
  const calls = [];
  const stages = [];
  const request = {
    ...fakeRequest(t),
    markStage(stage) {
      stages.push(stage);
    }
  };
  const service = fakeService(calls, request);
  const identifiers = [
    "synthetic-contact-url",
    "synthetic-contact-buffer",
    "synthetic-contact-both",
    "synthetic-contact-missing"
  ];
  service.getContactsCompact = async (...args) => {
    calls.push({name: "getContactsCompact", args});
    return {
      success: true,
      contacts: identifiers.map((username, index) => ({
        username,
        nick_name: `forbidden-nickname-${index}`,
        source_path: String.raw`X:\forbidden\contact-${index}`
      }))
    };
  };
  service.getAvatarUrls = async (...args) => {
    calls.push({name: "getAvatarUrls", args});
    return {
      success: true,
      map: {
        [identifiers[0]]: "https://example.invalid/avatar-url",
        [identifiers[2]]: "https://example.invalid/avatar-both"
      }
    };
  };
  service.getHeadImageBuffers = async (...args) => {
    calls.push({name: "getHeadImageBuffers", args});
    return {
      success: true,
      map: {
        [identifiers[1]]: "FFD8FFE0",
        [identifiers[2]]: "89504E47"
      }
    };
  };

  const result = await runAvatarAggregateGateway(service, request);

  assert.deepEqual(result, {
    status: "ok",
    reasonCode: null,
    avatarAggregate: {
      version: 1,
      candidateContactCount: 4,
      avatarUrlCount: 2,
      headImageBufferCount: 2,
      finalAvatarCount: 3,
      missingAvatarCount: 1,
      reasonCounts: {
        urlOnly: 1,
        headImageBufferOnly: 1,
        urlAndHeadImageBuffer: 1,
        noSupportedSource: 1
      }
    },
    callsBeforeOpen: ["setPaths", "testConnection"],
    nativeProtectionAuthenticated: true,
    workerSetPathsCalled: true
  });
  assert.deepEqual(
    calls.map(call => call.name),
    [
      "setPaths",
      "testConnection",
      "open",
      "getContactsCompact",
      "getAvatarUrls",
      "getHeadImageBuffers"
    ]
  );
  assert.deepEqual(calls[3].args, [[]]);
  assert.deepEqual(calls[4].args, [identifiers]);
  assert.deepEqual(calls[5].args, [identifiers]);
  const emitted = JSON.stringify({result, stages});
  for (const forbidden of [
    ...identifiers,
    "forbidden-nickname",
    "example.invalid",
    "FFD8FFE0",
    "89504E47",
    String.raw`X:\forbidden`
  ]) {
    assert.equal(emitted.includes(forbidden), false);
  }
  assert.deepEqual(stages, [
    "avatar_gateway_started",
    "paths_set",
    "connection_tested",
    "account_opened",
    "contacts_loaded",
    "avatar_urls_loaded",
    "head_image_buffers_loaded",
    "avatar_aggregate_ready"
  ]);
});

test("media probe fully paginates local image and video into counts only",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  const attachRoot = path.join(accountRoot, "msg", "attach");
  const videoRoot = path.join(accountRoot, "msg", "video");
  const hardlinkDb = path.join(
    request.dbStorageDir, "hardlink", "hardlink.db");
  const imagePath = path.join(
    attachRoot, "forbidden-session", "forbidden-image.dat");
  const resolvedVideoMd5 = `${"b".repeat(32)}_raw`;
  const videoPath = path.join(
    videoRoot, "forbidden-session", `${resolvedVideoMd5}.mp4`);
  fs.mkdirSync(path.dirname(imagePath), {recursive: true});
  fs.mkdirSync(path.dirname(videoPath), {recursive: true});
  fs.mkdirSync(path.dirname(hardlinkDb), {recursive: true});
  fs.writeFileSync(imagePath, Buffer.from("FFD8FFE000104A46", "hex"));
  fs.writeFileSync(videoPath, Buffer.from("000000186674797069736F6D", "hex"));
  fs.writeFileSync(hardlinkDb, "synthetic-hardlink");

  const service = fakeService(calls, request);
  service.getAggregateStats = async (...args) => {
    calls.push({name: "getAggregateStats", args});
    return {success: true, data: {total: 2, sessions: {}}};
  };
  service.getMediaStream = async options => {
    calls.push({name: "getMediaStream", args: [options]});
    if (options.offset === 0) {
      return {
        success: true,
        items: [{
          sessionId: "forbidden-session",
          localId: 11,
          localType: 3,
          createTime: 100,
          mediaType: "image",
          imageMd5: "a".repeat(32),
          imageDatName: "forbidden-image"
        }],
        hasMore: true,
        nextOffset: 1
      };
    }
    return {
      success: true,
      items: [{
        sessionId: "forbidden-session",
        localId: 12,
        localType: 43,
        createTime: 101,
        mediaType: "video",
        videoMd5: "c".repeat(32),
        content: "forbidden-message-content"
      }],
      hasMore: false,
      nextOffset: 2
    };
  };
  service.resolveImageHardlink = async (...args) => {
    calls.push({name: "resolveImageHardlink", args});
    return {
      success: true,
      data: {file_name: path.basename(imagePath), full_path: imagePath}
    };
  };
  service.resolveVideoHardlinkMd5 = async (...args) => {
    calls.push({name: "resolveVideoHardlinkMd5", args});
    return {success: true, data: {resolved_md5: resolvedVideoMd5}};
  };

  const result = await runMediaOpenabilityGateway(service, request);

  assert.deepEqual(result, {
    status: "ok",
    reasonCode: null,
    mediaOpenability: {
      version: 1,
      candidateCount: 2,
      imageCandidateCount: 1,
      videoCandidateCount: 1,
      locallyUnavailableCount: 0,
      localFileCount: 2,
      readableImageCount: 1,
      readableVideoCount: 1,
      unreadableLocalCount: 0
    },
    callsBeforeOpen: ["setPaths", "testConnection"],
    nativeProtectionAuthenticated: true,
    workerSetPathsCalled: true
  });
  const emitted = JSON.stringify(result);
  for (const forbidden of [
    "forbidden-session",
    "forbidden-image",
    "forbidden-message-content",
    resolvedVideoMd5,
    imagePath,
    videoPath
  ]) {
    assert.equal(emitted.includes(forbidden), false);
  }
});

test("media probe recognizes a synthetic WeFlow XOR DAT prefix in memory",
     async t => {
  const calls = [];
  const request = {...fakeRequest(t), imageXorKey: 0x5A};
  const accountRoot = path.dirname(request.dbStorageDir);
  const imagePath = path.join(
    accountRoot, "msg", "attach", "synthetic", "image.dat");
  fs.mkdirSync(path.dirname(imagePath), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const clearPrefix = Buffer.from("89504E470D0A1A0A0000000D49484452", "hex");
  fs.writeFileSync(
    imagePath,
    Buffer.from([...clearPrefix].map(
      byte => byte ^ request.imageXorKey)));

  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "synthetic-session",
      localId: 21,
      localType: 3,
      createTime: 200,
      mediaType: "image",
      imageMd5: "d".repeat(32),
      imageDatName: "image"
    }],
    hasMore: false,
    nextOffset: 1
  });
  service.resolveImageHardlink = async () => ({
    success: true,
    data: {file_name: path.basename(imagePath), full_path: imagePath}
  });

  const result = await runMediaOpenabilityGateway(service, request);

  assert.deepEqual(result.mediaOpenability, {
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
  assert.equal(JSON.stringify(result).includes("90"), false);
});

test("media probe recognizes a synthetic WeFlow V4 AES DAT prefix in memory",
     async t => {
  const calls = [];
  const imageAesKey = "0123456789abcdef";
  const request = {
    ...fakeRequest(t),
    imageXorKey: 0x5A,
    imageAesKey
  };
  const accountRoot = path.dirname(request.dbStorageDir);
  const imagePath = path.join(
    accountRoot, "msg", "attach", "synthetic", "image-v4.dat");
  fs.mkdirSync(path.dirname(imagePath), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const clearBlock = Buffer.from(
    "FFD8FFE000104A464946000101000001", "hex");
  const cipher = crypto.createCipheriv(
    "aes-128-ecb", Buffer.from(imageAesKey, "ascii"), null);
  cipher.setAutoPadding(false);
  const encryptedBlock = Buffer.concat([cipher.update(clearBlock), cipher.final()]);
  const header = Buffer.alloc(15);
  Buffer.from([7, 8, 86, 50, 8, 7]).copy(header);
  header.writeInt32LE(16, 6);
  header.writeInt32LE(0, 10);
  fs.writeFileSync(imagePath, Buffer.concat([header, encryptedBlock]));

  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "synthetic-session",
      localId: 22,
      localType: 3,
      createTime: 201,
      mediaType: "image",
      imageMd5: "e".repeat(32),
      imageDatName: "image-v4"
    }],
    hasMore: false,
    nextOffset: 1
  });
  service.resolveImageHardlink = async () => ({
    success: true,
    data: {file_name: path.basename(imagePath), full_path: imagePath}
  });

  const result = await runMediaOpenabilityGateway(service, request);

  assert.equal(result.mediaOpenability.readableImageCount, 1);
  assert.equal(result.mediaOpenability.unreadableLocalCount, 0);
  assert.equal(JSON.stringify(result).includes(imageAesKey), false);
});

test("media probe resolves a local image from the pinned DAT name only",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  const datName = "f".repeat(32);
  const imagePath = path.join(
    accountRoot, "msg", "attach", "synthetic", `${datName}.dat`);
  fs.mkdirSync(path.dirname(imagePath), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  fs.writeFileSync(imagePath, Buffer.from("FFD8FFE000104A46", "hex"));

  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "synthetic-session",
      localId: 23,
      localType: 3,
      createTime: 202,
      mediaType: "image",
      imageDatName: datName
    }],
    hasMore: false,
    nextOffset: 1
  });

  const result = await runMediaOpenabilityGateway(service, request);

  assert.equal(result.mediaOpenability.readableImageCount, 1);
  assert.equal(result.mediaOpenability.locallyUnavailableCount, 0);
});

test("media probe falls back after an empty successful image hardlink result",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  const token = "a".repeat(32);
  const imagePath = path.join(
    accountRoot, "msg", "attach", "synthetic", `${token}.dat`);
  fs.mkdirSync(path.dirname(imagePath), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  fs.writeFileSync(imagePath, Buffer.from("FFD8FFE000104A46", "hex"));

  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "synthetic-session",
      localId: 24,
      localType: 3,
      createTime: 203,
      mediaType: "image",
      imageMd5: token
    }],
    hasMore: false,
    nextOffset: 1
  });
  service.resolveImageHardlink = async () => ({success: true, data: {}});

  const result = await runMediaOpenabilityGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(result.mediaOpenability.readableImageCount, 1);
  assert.equal(result.mediaOpenability.locallyUnavailableCount, 0);
});

test("media probe counts an empty successful hardlink miss as unavailable",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  fs.mkdirSync(path.join(accountRoot, "msg", "attach"), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "synthetic-session",
      localId: 25,
      localType: 3,
      createTime: 204,
      mediaType: "image",
      imageMd5: "b".repeat(32)
    }],
    hasMore: false,
    nextOffset: 1
  });
  service.resolveImageHardlink = async () => ({success: true, data: {}});

  const result = await runMediaOpenabilityGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(result.mediaOpenability.locallyUnavailableCount, 1);
  assert.equal(result.mediaOpenability.localFileCount, 0);
});

test("media probe rejects partial or malformed image hardlink paths",
     async t => {
  const cases = [
    ["file name only", imagePath => ({file_name: path.basename(imagePath)})],
    ["full path only", imagePath => ({full_path: imagePath})],
    ["file name type drift", imagePath => ({
      file_name: 1, full_path: imagePath
    })],
    ["full path type drift", imagePath => ({
      file_name: path.basename(imagePath), full_path: 1
    })],
    ["basename mismatch", imagePath => ({
      file_name: "other.dat", full_path: imagePath
    })]
  ];
  for (const [name, responseData] of cases) {
    await t.test(name, async child => {
      const calls = [];
      const request = fakeRequest(child);
      const accountRoot = path.dirname(request.dbStorageDir);
      const imagePath = path.join(
        accountRoot, "msg", "attach", "synthetic", "image.dat");
      fs.mkdirSync(path.dirname(imagePath), {recursive: true});
      fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
      fs.writeFileSync(imagePath, Buffer.from("FFD8FFE000104A46", "hex"));
      const service = fakeService(calls, request);
      service.getAggregateStats = async () => (
        {success: true, data: {total: 1, sessions: {}}}
      );
      service.getMediaStream = async () => ({
        success: true,
        items: [{
          sessionId: "synthetic-session",
          localId: 26,
          localType: 3,
          createTime: 205,
          mediaType: "image",
          imageMd5: "c".repeat(32)
        }],
        hasMore: false,
        nextOffset: 1
      });
      service.resolveImageHardlink = async () => ({
        success: true, data: responseData(imagePath)
      });

      const result = await runMediaOpenabilityGateway(service, request);

      assert.equal(result.status, "compatibility_blocked");
      assert.equal(result.reasonCode, "media_probe_failed");
      assert.equal(result.validation, null);
    });
  }
});

test("media probe rejects worker candidate type drift without details",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  fs.mkdirSync(path.join(accountRoot, "msg", "attach"), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "forbidden-session-detail",
      localId: "24",
      localType: 3,
      createTime: 203,
      mediaType: "image",
      imageMd5: "a".repeat(32)
    }],
    hasMore: false,
    nextOffset: 1
  });
  let resolverCalls = 0;
  service.resolveImageHardlink = async () => {
    resolverCalls += 1;
    return {success: false};
  };

  const result = await runMediaOpenabilityGateway(service, request);

  assert.deepEqual(result, {
    status: "compatibility_blocked",
    reasonCode: "media_probe_failed",
    validation: null,
    callsBeforeOpen: ["setPaths", "testConnection"],
    nativeProtectionAuthenticated: false,
    workerSetPathsCalled: true
  });
  assert.equal(resolverCalls, 0);
  assert.equal(JSON.stringify(result).includes("forbidden-session-detail"), false);
});

test("media probe counts a missing local item without network access",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  fs.mkdirSync(path.join(accountRoot, "msg", "attach"), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "synthetic-session",
      localId: 25,
      localType: 3,
      createTime: 204,
      mediaType: "image",
      imageMd5: "a".repeat(32)
    }],
    hasMore: false,
    nextOffset: 1
  });
  service.resolveImageHardlink = async () => ({success: false});

  const result = await runMediaOpenabilityGateway(service, request);

  assert.deepEqual(result.mediaOpenability, {
    version: 1,
    candidateCount: 1,
    imageCandidateCount: 1,
    videoCandidateCount: 0,
    locallyUnavailableCount: 1,
    localFileCount: 0,
    readableImageCount: 0,
    readableVideoCount: 0,
    unreadableLocalCount: 0
  });
  assert.equal(calls.some(call => /url|fetch|network/i.test(call.name)), false);
});

test("media probe rejects pagination drift without candidate details",
     async t => {
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  fs.mkdirSync(path.join(accountRoot, "msg", "attach"), {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const candidate = {
    sessionId: "forbidden-repeated-session",
    localId: 26,
    localType: 3,
    createTime: 205,
    mediaType: "image",
    imageMd5: "b".repeat(32)
  };
  const cases = [
    {
      name: "empty non-terminal page",
      page: () => ({
        success: true, items: [], hasMore: true, nextOffset: 0
      })
    },
    {
      name: "non-advancing offset",
      page: () => ({
        success: true, items: [candidate], hasMore: false, nextOffset: 0
      })
    },
    {
      name: "repeated candidate",
      page: options => ({
        success: true,
        items: [candidate],
        hasMore: options.offset === 0,
        nextOffset: options.offset + 1
      })
    }
  ];
  for (const item of cases) {
    await t.test(item.name, async () => {
      const calls = [];
      const service = fakeService(calls, request);
      service.getAggregateStats = async () => (
        {success: true, data: {total: 2, sessions: {}}}
      );
      service.getMediaStream = item.page;
      service.resolveImageHardlink = async () => ({success: false});

      const result = await runMediaOpenabilityGateway(service, request);

      assert.deepEqual(result, {
        status: "compatibility_blocked",
        reasonCode: "media_probe_failed",
        validation: null,
        callsBeforeOpen: ["setPaths", "testConnection"],
        nativeProtectionAuthenticated: false,
        workerSetPathsCalled: true
      });
      assert.equal(
        JSON.stringify(result).includes("forbidden-repeated-session"), false);
    });
  }
});

test("media probe separates readable WebP from unreadable local media",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  const attachRoot = path.join(accountRoot, "msg", "attach", "synthetic");
  fs.mkdirSync(attachRoot, {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const readable = path.join(attachRoot, "readable.webp");
  const unreadable = path.join(attachRoot, "unreadable.dat");
  fs.writeFileSync(readable, Buffer.from("524946460400000057454250", "hex"));
  fs.writeFileSync(unreadable, Buffer.from("0102030405060708", "hex"));
  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 2, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [
      {sessionId: "s", localId: 27, localType: 3, createTime: 206,
        mediaType: "image", imageMd5: "c".repeat(32)},
      {sessionId: "s", localId: 28, localType: 3, createTime: 207,
        mediaType: "image", imageMd5: "d".repeat(32)}
    ],
    hasMore: false,
    nextOffset: 2
  });
  service.resolveImageHardlink = async md5 => ({
    success: true,
    data: {
      file_name: path.basename(md5.startsWith("c") ? readable : unreadable),
      full_path: md5.startsWith("c") ? readable : unreadable
    }
  });

  const result = await runMediaOpenabilityGateway(service, request);

  assert.equal(result.mediaOpenability.readableImageCount, 1);
  assert.equal(result.mediaOpenability.unreadableLocalCount, 1);
  assert.equal(result.mediaOpenability.localFileCount, 2);
});

test("media probe rejects a resolved path escape", async t => {
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  const attachRoot = path.join(accountRoot, "msg", "attach");
  fs.mkdirSync(attachRoot, {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const outside = path.join(accountRoot, "outside.dat");
  fs.writeFileSync(outside, Buffer.from("FFD8FFE0", "hex"));
  const candidate = {
    sessionId: "forbidden-path-session",
    localId: 29,
    localType: 3,
    createTime: 208,
    mediaType: "image",
    imageMd5: "f".repeat(32)
  };
  const calls = [];
  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [candidate],
    hasMore: false,
    nextOffset: 1
  });
  service.resolveImageHardlink = async () => ({
    success: true,
    data: {file_name: path.basename(outside), full_path: outside}
  });

  const result = await runMediaOpenabilityGateway(service, request);

  assert.equal(result.status, "compatibility_blocked");
  assert.equal(result.reasonCode, "media_probe_failed");
  assert.equal(result.validation, null);
  assert.equal(
    JSON.stringify(result).includes("forbidden-path-session"), false);
});

test("media probe does not choose an ambiguous indexed media name",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  const attachRoot = path.join(accountRoot, "msg", "attach");
  fs.mkdirSync(attachRoot, {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const token = "e".repeat(32);
  fs.writeFileSync(path.join(attachRoot, `${token}.dat`), "one");
  fs.writeFileSync(path.join(attachRoot, `${token}.jpg`), "two");
  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "ambiguous-local-session",
      localId: 30,
      localType: 3,
      createTime: 208,
      mediaType: "image",
      imageDatName: token
    }],
    hasMore: false,
    nextOffset: 1
  });
  service.resolveImageHardlink = async () => ({success: false});

  const result = await runMediaOpenabilityGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(result.reasonCode, null);
  assert.deepEqual(result.mediaOpenability, {
    version: 1,
    candidateCount: 1,
    imageCandidateCount: 1,
    videoCandidateCount: 0,
    locallyUnavailableCount: 1,
    localFileCount: 0,
    readableImageCount: 0,
    readableVideoCount: 0,
    unreadableLocalCount: 0
  });
});

test("media probe ignores an unrelated duplicate media index name",
     async t => {
  const calls = [];
  const request = fakeRequest(t);
  const stages = [];
  request.markStage = stage => stages.push(stage);
  const accountRoot = path.dirname(request.dbStorageDir);
  const attachRoot = path.join(accountRoot, "msg", "attach");
  fs.mkdirSync(attachRoot, {recursive: true});
  fs.mkdirSync(path.join(accountRoot, "msg", "video"), {recursive: true});
  const duplicate = "1".repeat(32);
  fs.writeFileSync(path.join(attachRoot, `${duplicate}.dat`), "one");
  fs.writeFileSync(path.join(attachRoot, `${duplicate}.jpg`), "two");
  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 1, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true,
    items: [{
      sessionId: "synthetic-session",
      localId: 31,
      localType: 3,
      createTime: 209,
      mediaType: "image",
      imageDatName: "2".repeat(32)
    }],
    hasMore: false,
    nextOffset: 1
  });

  const result = await runMediaOpenabilityGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(result.reasonCode, null);
  assert.deepEqual(result.mediaOpenability, {
    version: 1,
    candidateCount: 1,
    imageCandidateCount: 1,
    videoCandidateCount: 0,
    locallyUnavailableCount: 1,
    localFileCount: 0,
    readableImageCount: 0,
    readableVideoCount: 0,
    unreadableLocalCount: 0
  });
  assert.deepEqual(stages, [
    "media_gateway_started", "paths_set", "connection_tested",
    "account_opened", "sessions_loaded", "aggregate_loaded",
    "media_index_started", "media_index_ready", "media_stream_started",
    "media_stream_page_loaded", "media_candidate_identity_ready",
    "media_candidate_unique", "media_image_inspect_started",
    "media_image_md5_ready", "media_image_token_ready",
    "media_image_index_lookup_ready", "media_image_unavailable",
    "media_image_inspect_ready", "media_candidate_counted",
    "media_probe_ready"
  ]);
});

test("media probe never follows a linked media root", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const accountRoot = path.dirname(request.dbStorageDir);
  const msgRoot = path.join(accountRoot, "msg");
  const outside = path.join(accountRoot, "outside-attach");
  fs.mkdirSync(msgRoot, {recursive: true});
  fs.mkdirSync(outside);
  fs.mkdirSync(path.join(msgRoot, "video"));
  try {
    fs.symlinkSync(outside, path.join(msgRoot, "attach"), "dir");
  } catch {
    t.skip("directory symlink creation unavailable");
    return;
  }
  const service = fakeService(calls, request);
  service.getAggregateStats = async () => (
    {success: true, data: {total: 0, sessions: {}}}
  );
  service.getMediaStream = async () => ({
    success: true, items: [], hasMore: false, nextOffset: 0
  });

  const result = await runMediaOpenabilityGateway(service, request);

  assert.equal(result.status, "compatibility_blocked");
  assert.equal(result.reasonCode, "media_probe_failed");
  assert.equal(result.validation, null);
});

test("official database folders use their fixed read-only kind", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const favorite = path.join(
    request.dbStorageDir, "favorite", "favorite.db");
  fs.mkdirSync(path.dirname(favorite), {recursive: true});
  fs.writeFileSync(favorite, "synthetic-favorite");
  const service = fakeService(calls, request);

  const result = await runSnapshotGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(
    calls.some(call => call.name === "listTables" &&
      call.args[0] === "favorite" &&
      path.normalize(call.args[1]) === path.normalize(favorite)),
    true
  );
});

test("migrate databases use their fixed read-only kind", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const migrate = path.join(
    request.dbStorageDir, "migrate", "migrate.db");
  fs.mkdirSync(path.dirname(migrate), {recursive: true});
  fs.writeFileSync(migrate, "synthetic-migrate");
  const service = fakeService(calls, request);

  const result = await runSnapshotGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(
    calls.some(call => call.name === "listTables" &&
      call.args[0] === "migrate" &&
      path.normalize(call.args[1]) === path.normalize(migrate)),
    true
  );
  assert.equal(result.validation.databaseCount, 3);
});

test("official zero-table database remains in coverage", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const favorite = path.join(
    request.dbStorageDir, "favorite", "favorite.db");
  fs.mkdirSync(path.dirname(favorite), {recursive: true});
  fs.writeFileSync(favorite, "synthetic-favorite");
  const service = fakeService(calls, request);
  const listTables = service.listTables;
  service.listTables = async (...args) => {
    if (args[0] === "favorite") {
      calls.push({name: "listTables", args});
      return {success: true, tables: []};
    }
    return listTables(...args);
  };

  const result = await runSnapshotGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(result.validation.databaseCount, 3);
  assert.equal(result.validation.tableCount, 2);
});

test("message auxiliary tables need schema but not message stats", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const service = fakeService(calls, request);
  const listTables = service.listTables;
  service.listTables = async (...args) => {
    if (args[0] === "message") {
      calls.push({name: "listTables", args});
      return {success: true, tables: ["auxiliary", "message"]};
    }
    return listTables(...args);
  };

  const result = await runSnapshotGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(
    calls.filter(call => call.name === "getTableSchema" &&
      call.args[0] === "message").length,
    2
  );
  assert.equal(
    calls.filter(call => call.name === "getMessageTableTimeRange").length,
    1
  );
});

test("empty dynamic message shard remains covered when totals agree",
     async t => {
  const calls = [];
  const stages = [];
  const request = {
    ...fakeRequest(t),
    markStage(stage) {
      stages.push(stage);
    }
  };
  const service = fakeService(calls, request);
  service.getMessageTableStats = async (...args) => {
    calls.push({name: "getMessageTableStats", args});
    return {success: true, tables: []};
  };

  const result = await runSnapshotGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(result.validation.databaseCount, 2);
  assert.equal(result.validation.tableCount, 2);
  assert.equal(result.validation.recordCount, 0);
  assert.equal(stages.at(-1), "fingerprints_ready");
  assert.equal(stages.join("\n").includes(request.dbStorageDir), false);
});

test("missing message stats cannot hide native aggregate records", async t => {
  const calls = [];
  const stages = [];
  const request = {
    ...fakeRequest(t),
    markStage(stage) {
      stages.push(stage);
    }
  };
  const service = fakeService(calls, request);
  service.getAggregateStats = async (...args) => {
    calls.push({name: "getAggregateStats", args});
    return {success: true, data: {total: 1, sessions: {}}};
  };
  service.getMessageTableStats = async (...args) => {
    calls.push({name: "getMessageTableStats", args});
    return {success: true, tables: []};
  };

  await assert.rejects(
    runSnapshotGateway(service, request),
    /worker_contract_mismatch/
  );

  assert.equal(stages.at(-1), "message_stats_loaded");
});

test("dynamic media kind overrides the message folder fallback", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const oldMedia = path.join(
    request.dbStorageDir, "media", "media_0.db");
  fs.rmSync(oldMedia);
  const media = path.join(
    request.dbStorageDir, "message", "media_0.db");
  fs.writeFileSync(media, "synthetic-media");
  const service = fakeService(calls, request);
  service.listMediaDbs = async (...args) => {
    calls.push({name: "listMediaDbs", args});
    return {success: true, data: [media]};
  };

  const result = await runSnapshotGateway(service, request);

  assert.equal(result.status, "ok");
  assert.equal(
    calls.some(call => call.name === "listTables" &&
      call.args[0] === "media" &&
      path.normalize(call.args[1]) === path.normalize(media)),
    true
  );
});

test("duplicate dynamic database keys are rejected", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const service = fakeService(calls, request);
  const absolute = path.join(
    request.dbStorageDir, "message", "message_0.db"
  );
  service.listMessageDbs = async (...args) => {
    calls.push({name: "listMessageDbs", args});
    return {
      success: true,
      data: [absolute, path.relative(request.dbStorageDir, absolute)]
    };
  };
  await assert.rejects(
    runSnapshotGateway(service, request),
    /worker_contract_mismatch/
  );
});

test("dynamic lists cannot reclassify a fixed database kind", async t => {
  const calls = [];
  const request = fakeRequest(t);
  const session = path.join(request.dbStorageDir, "session.db");
  fs.writeFileSync(session, "synthetic-session");
  const service = fakeService(calls, request);
  service.listMessageDbs = async (...args) => {
    calls.push({name: "listMessageDbs", args});
    return {
      success: true,
      data: [
        path.join(
          request.dbStorageDir, "message", "message_0.db"
        ),
        session
      ]
    };
  };
  service.getMessageTableStats = async (...args) => {
    calls.push({name: "getMessageTableStats", args});
    return {
      success: true,
      tables: [
        {
          db_path: path.join(
            request.dbStorageDir, "message", "message_0.db"
          ),
          table_name: "message",
          count: 0
        },
        {
          db_path: session,
          table_name: "message",
          count: 0
        }
      ]
    };
  };
  await assert.rejects(
    runSnapshotGateway(service, request),
    /worker_contract_mismatch/
  );
});
