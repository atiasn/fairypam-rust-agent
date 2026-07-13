const crypto = require("crypto");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const executable = process.env.FAIRYPAM_CANDIDATE_EXE;
const buildId = process.env.FAIRYPAM_CANDIDATE_BUILD_ID;
const sourceCommit = process.env.FAIRYPAM_CANDIDATE_SOURCE_COMMIT;
const packageSha256 = process.env.FAIRYPAM_CANDIDATE_SHA256;
const evidencePath = process.env.FAIRYPAM_CANDIDATE_EVIDENCE_PATH;

for (const [name, value] of Object.entries({
  FAIRYPAM_CANDIDATE_EXE: executable,
  FAIRYPAM_CANDIDATE_BUILD_ID: buildId,
  FAIRYPAM_CANDIDATE_SOURCE_COMMIT: sourceCommit,
  FAIRYPAM_CANDIDATE_SHA256: packageSha256,
  FAIRYPAM_CANDIDATE_EVIDENCE_PATH: evidencePath,
})) {
  if (!value) throw new Error(`${name} is required`);
}
if (!fs.statSync(executable).isFile()) throw new Error(`candidate executable not found: ${executable}`);

const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "fairypam-package-smoke-"));
const logPath = path.join(workdir, "logs", "agent.log");
const configPath = path.join(workdir, "config.yaml");
let child = null;
let finishing = false;
let sawHello = false;
let sawHeartbeat = false;
let logInitialized = false;
let processCleaned = false;

function encodeFrame(opcode, payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  if (data.length >= 65536) throw new Error("smoke WebSocket payload too large");
  const header = data.length < 126
    ? Buffer.from([0x80 | opcode, data.length])
    : Buffer.from([0x80 | opcode, 126, (data.length >> 8) & 0xff, data.length & 0xff]);
  return Buffer.concat([header, data]);
}

function parseFrames(buffer, onFrame) {
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    let headerLength = 2;
    if (length === 126) {
      if (buffer.length - offset < 4) break;
      length = buffer.readUInt16BE(offset + 2);
      headerLength = 4;
    } else if (length === 127) {
      throw new Error("smoke WebSocket frame is unexpectedly large");
    }
    const maskLength = masked ? 4 : 0;
    const frameLength = headerLength + maskLength + length;
    if (buffer.length - offset < frameLength) break;
    const mask = masked ? buffer.subarray(offset + headerLength, offset + headerLength + 4) : null;
    const payload = Buffer.from(buffer.subarray(offset + headerLength + maskLength, offset + frameLength));
    if (mask) {
      for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index % 4];
    }
    onFrame(first & 0x0f, payload);
    offset += frameLength;
  }
  return buffer.subarray(offset);
}

function waitForExit(timeoutMs) {
  if (!child || child.exitCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(false), timeoutMs);
    child.once("exit", () => {
      clearTimeout(timeout);
      resolve(true);
    });
  });
}

async function stopChild() {
  if (!child || child.exitCode !== null) return true;
  child.kill();
  if (await waitForExit(3000)) return true;
  child.kill("SIGKILL");
  return waitForExit(3000);
}

function writeEvidence(evidence) {
  fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
  fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
}

async function finish(server, ok, message) {
  if (finishing) return;
  finishing = true;
  clearTimeout(deadline);
  server.close();
  processCleaned = await stopChild();
  logInitialized =
    fs.existsSync(logPath) &&
    fs.readFileSync(logPath, "utf8").includes("FairyPam Agent starting");
  const passed = ok && sawHello && sawHeartbeat && logInitialized && processCleaned;
  const evidence = {
    schema_version: 1,
    gate: "RUST-CLI-SAFE",
    ok: passed,
    build_id: buildId,
    source_commit: sourceCommit,
    sha256: packageSha256,
    saw_hello: sawHello,
    saw_heartbeat: sawHeartbeat,
    log_initialized: logInitialized,
    process_cleaned: processCleaned,
    completed_at: new Date().toISOString(),
    message,
  };
  writeEvidence(evidence);
  fs.rmSync(workdir, { recursive: true, force: true });
  if (passed) {
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
    process.exit(0);
  }
  console.error(`package smoke failed: ${message}`);
  process.exit(1);
}

const server = net.createServer((socket) => {
  let handshaken = false;
  let pending = Buffer.alloc(0);
  socket.on("error", (error) => {
    if (!finishing) void finish(server, false, `socket error: ${error.code || error.message}`);
  });
  socket.on("data", (chunk) => {
    try {
      pending = Buffer.concat([pending, chunk]);
      if (!handshaken) {
        const text = pending.toString("utf8");
        const headerEnd = text.indexOf("\r\n\r\n");
        if (headerEnd === -1) return;
        const keyLine = text
          .split("\r\n")
          .find((line) => line.toLowerCase().startsWith("sec-websocket-key:"));
        if (!keyLine) throw new Error("missing WebSocket key");
        const key = keyLine.split(":").slice(1).join(":").trim();
        const accept = crypto
          .createHash("sha1")
          .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
          .digest("base64");
        socket.write(
          [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            `Sec-WebSocket-Accept: ${accept}`,
            "\r\n",
          ].join("\r\n"),
        );
        handshaken = true;
        pending = pending.subarray(Buffer.byteLength(text.slice(0, headerEnd + 4)));
      }
      pending = parseFrames(pending, (opcode, payload) => {
        if (opcode !== 0x1) return;
        const message = JSON.parse(payload.toString("utf8"));
        if (message.type === "agent_hello") {
          sawHello = true;
          socket.write(
            encodeFrame(
              0x1,
              JSON.stringify({
                type: "hub_welcome",
                protocol_version: 3,
                agent_id: "00000000-0000-0000-0000-000000000001",
                agent_name_effective: "candidate-smoke",
                config: {
                  heartbeat_interval_s: 1,
                  command_timeout_s: 5,
                  auto_update: false,
                  auto_start: false,
                  launch_allowlist: [],
                },
                accepted_capabilities: message.capabilities || [],
              }),
            ),
          );
        } else if (message.type === "heartbeat") {
          sawHeartbeat = true;
          void finish(server, true, "packaged agent hello and heartbeat observed");
        }
      });
    } catch (error) {
      void finish(server, false, error.message);
    }
  });
});

server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  fs.writeFileSync(
    configPath,
    [
      "hub:",
      `  ws_url: \"ws://127.0.0.1:${port}/ws\"`,
      '  api_key: "candidate-smoke-placeholder"',
      "agent:",
      '  name: "candidate-smoke"',
      '  log_level: "info"',
      "capture:",
      "  target_display: 0",
      "  fps: 0",
      "  jpeg_quality: 40",
      '  encoder: "gdi"',
      "",
    ].join("\n"),
    "utf8",
  );
  child = spawn(executable, ["--run", "--config", configPath, "--log-file", logPath], {
    cwd: workdir,
    windowsHide: true,
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr = `${stderr}${chunk}`.slice(-2000);
  });
  child.on("error", (error) => void finish(server, false, error.message));
  child.on("exit", (code) => {
    if (!finishing) void finish(server, false, `candidate exited early: ${code}; ${stderr.trim()}`);
  });
});

const deadline = setTimeout(() => {
  void finish(
    server,
    false,
    `timeout; sawHello=${sawHello} sawHeartbeat=${sawHeartbeat}`,
  );
}, 15000);
