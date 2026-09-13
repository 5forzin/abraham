"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const net = require("node:net");
const { test } = require("node:test");
const {
  createAppServer,
  extractOpenAIText,
  managementAddress,
  requestManagement,
  safeResults,
  safeSessions,
} = require("./server.cjs");

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function requestWithHost(port, host) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: "127.0.0.1",
        port,
        path: "/operator-api/sessions",
        headers: { Host: host, "X-Abraham-Client": "operator-ui" },
      },
      (response) => {
        response.resume();
        response.on("end", () => resolve(response.statusCode));
      },
    );
    request.on("error", reject);
    request.end();
  });
}

test("managementAddress parses host and port", () => {
  assert.deepEqual(managementAddress("127.0.0.1:9200"), {
    host: "127.0.0.1",
    port: 9200,
  });
  assert.throws(() => managementAddress("invalid"));
  assert.throws(() => managementAddress("management.example:9200"), /loopback/);
});

test("management data is bounded and normalized", () => {
  assert.deepEqual(
    safeSessions({ sessions: [{ id: "4", hostname: "lab", stale: 1 }] }),
    [
      {
        id: 4,
        hostname: "lab",
        username: "",
        domain: "",
        user: "",
        pid: 0,
        ppid: 0,
        arch: "",
        integrity_level: 0,
        os_build: "",
        addr: "",
        last_seen: 0,
        age: 0,
        stale: true,
        implant_version: "",
        pending_tasks: 0,
      },
    ],
  );
  assert.equal(
    safeResults({ results: [{ summary: "x".repeat(800) }] })[0].summary.length,
    500,
  );
});

test("OpenAI text is extracted from Responses API output", () => {
  assert.equal(
    extractOpenAIText({
      output: [{ type: "message", content: [{ type: "output_text", text: "ok" }] }],
    }),
    "ok",
  );
  assert.equal(
    extractOpenAIText({
      output: [{ type: "message", content: [{ type: "refusal", refusal: "recusado" }] }],
    }),
    "recusado",
  );
});

test("management client authenticates before its read-only request", async () => {
  const received = [];
  const management = net.createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffer += chunk;
      let newline;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const request = JSON.parse(buffer.slice(0, newline));
        buffer = buffer.slice(newline + 1);
        received.push(request);
        if (request.auth) socket.write('{"ok":true}\n');
        else socket.end('{"sessions":[]}\n');
      }
    });
  });
  const port = await listen(management);
  try {
    const response = await requestManagement(
      { cmd: "sessions" },
      { address: `127.0.0.1:${port}`, token: "test-token" },
    );
    assert.deepEqual(response, { sessions: [] });
    assert.deepEqual(received, [{ auth: "test-token" }, { cmd: "sessions" }]);
  } finally {
    await close(management);
  }
});

test("HTTP gateway exposes only normalized read-only management routes", async () => {
  const requests = [];
  const server = createAppServer({
    requestManagement: async (request) => {
      requests.push(request);
      if (request.cmd === "sessions") return { sessions: [{ id: 2, hostname: "host" }] };
      return { results: [{ task_id: 7, summary: "complete" }] };
    },
    askOpenAI: async () => "answer",
  });
  const port = await listen(server);
  try {
    const sessions = await fetch(`http://127.0.0.1:${port}/operator-api/sessions`, {
      headers: { "X-Abraham-Client": "operator-ui" },
    }).then((r) => r.json());
    const results = await fetch(
      `http://127.0.0.1:${port}/operator-api/sessions/2/results?limit=999`,
      { headers: { "X-Abraham-Client": "operator-ui" } },
    ).then((r) => r.json());
    const blocked = await fetch(`http://127.0.0.1:${port}/operator-api/shell`, {
      method: "POST",
      headers: { "X-Abraham-Client": "operator-ui" },
    });
    const crossOrigin = await fetch(`http://127.0.0.1:${port}/operator-api/assistant`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Abraham-Client": "operator-ui",
        Origin: "https://attacker.example",
      },
      body: JSON.stringify({ message: "status" }),
    });
    const wrongType = await fetch(`http://127.0.0.1:${port}/operator-api/assistant`, {
      method: "POST",
      headers: { "Content-Type": "text/plain", "X-Abraham-Client": "operator-ui" },
      body: JSON.stringify({ message: "status" }),
    });
    const rebound = await requestWithHost(port, "attacker.example");
    const assistant = await fetch(`http://127.0.0.1:${port}/operator-api/assistant`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Abraham-Client": "operator-ui",
      },
      body: JSON.stringify({ message: "status" }),
    }).then((r) => r.json());
    const pageResponse = await fetch(`http://127.0.0.1:${port}/`);
    const page = await pageResponse.text();

    assert.equal(sessions.sessions[0].hostname, "host");
    assert.equal(results.results[0].task_id, 7);
    assert.equal(blocked.status, 404);
    assert.equal(crossOrigin.status, 403);
    assert.equal(wrongType.status, 415);
    assert.equal(rebound, 403);
    assert.equal(assistant.answer, "answer");
    assert.match(page, /Abraham C2/);
    assert.match(pageResponse.headers.get("content-security-policy"), /frame-ancestors 'none'/);
    assert.deepEqual(requests, [
      { cmd: "sessions" },
      { cmd: "results", session: 2, limit: 50 },
    ]);
  } finally {
    await close(server);
  }
});
