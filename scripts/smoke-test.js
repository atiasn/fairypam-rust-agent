const crypto = require("crypto");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const { execFile, spawn } = require("child_process");

const port = Number(process.env.FAIRYPAM_SMOKE_PORT || 17891);
const agentExe = path.resolve(__dirname, "..", "target", "debug", "fairypam-agent.exe");
const suite = (process.env.FAIRYPAM_SMOKE_SUITE || "safe").toLowerCase();
const captureFps = suite === "device" ? 30 : 0;
const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "fairypam-agent-smoke-"));
const logPath = path.join(workdir, "logs", "agent.log");
const configPath = path.join(workdir, "config.yaml");

fs.writeFileSync(
  configPath,
  [
    "hub:",
    `  ws_url: "ws://127.0.0.1:${port}/ws"`,
    '  api_key: "smoke-test-key"',
    "",
    "agent:",
    '  name: "smoke-agent"',
    '  log_level: "info"',
    "",
    "capture:",
    "  target_display: 0",
    `  fps: ${captureFps}`,
    "  jpeg_quality: 40",
    '  encoder: "gdi"',
    "",
  ].join("\n")
);

let sawHello = false;
let sawHeartbeat = false;
let logCheckScheduled = false;
let runtimeStarted = false;
let finishing = false;
const evidence = { suite };

function runCli(args) {
  return new Promise((resolve, reject) => {
    execFile(
      agentExe,
      ["--config", configPath, "--log-file", logPath, "automation", ...args],
      { cwd: workdir, windowsHide: true },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`${args.join(" ")} failed: ${stderr || error.message}`));
          return;
        }
        resolve(stdout.trim());
      },
    );
  });
}

function startRuntimeCli() {
  return new Promise((resolve, reject) => {
    const args = ["runtime", "start", "--test-only", "--json"];
    const child = spawn(
      agentExe,
      ["--config", configPath, "--log-file", logPath, "automation", ...args],
      { cwd: workdir, windowsHide: true },
    );
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("runtime start timed out after 10 seconds"));
    }, 10000);
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("exit", (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(`${args.join(" ")} failed: ${stderr.trim() || `exit code ${code}`}`));
        return;
      }
      resolve(stdout.trim());
    });
  });
}

function encodeFrame(opcode, payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const header = [];
  header.push(0x80 | opcode);
  if (data.length < 126) {
    header.push(data.length);
  } else if (data.length < 65536) {
    header.push(126, (data.length >> 8) & 0xff, data.length & 0xff);
  } else {
    throw new Error("payload too large for smoke test");
  }
  return Buffer.concat([Buffer.from(header), data]);
}

function parseFrames(buffer, onFrame) {
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    let headerLen = 2;

    if (length === 126) {
      if (buffer.length - offset < 4) break;
      length = buffer.readUInt16BE(offset + 2);
      headerLen = 4;
    } else if (length === 127) {
      if (buffer.length - offset < 10) break;
      const bigLength = buffer.readBigUInt64BE(offset + 2);
      if (bigLength > BigInt(Number.MAX_SAFE_INTEGER)) {
        void finish(false, "websocket frame too large for smoke test");
        return Buffer.alloc(0);
      }
      length = Number(bigLength);
      headerLen = 10;
    }

    const maskLen = masked ? 4 : 0;
    const frameLen = headerLen + maskLen + length;
    if (buffer.length - offset < frameLen) break;

    const mask = masked ? buffer.subarray(offset + headerLen, offset + headerLen + 4) : null;
    const payload = Buffer.from(buffer.subarray(offset + headerLen + maskLen, offset + frameLen));
    if (mask) {
      for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
    }

    onFrame(opcode, payload);
    offset += frameLen;
  }

  return buffer.subarray(offset);
}

async function finish(ok, message) {
  if (finishing) return;
  finishing = true;
  clearTimeout(timeout);
  try {
    if (ok) {
      evidence.runtime_status = JSON.parse(await runCli(["runtime", "status", "--json"]));
      evidence.metrics = JSON.parse(await runCli(["metrics", "--json"]));
      evidence.logs = await runCli(["logs", "tail", "--lines", "20"]);
      evidence.self_test_basic = JSON.parse(
        await runCli(["self-test", "run", "--suite", "basic", "--profile", "genshin", "--test-only"]),
      );
      if (suite === "device") {
        evidence.self_test_capture = JSON.parse(
          await runCli([
            "self-test",
            "run",
            "--suite",
            "capture",
            "--profile",
            "genshin",
            "--test-only",
            "--allow-capture",
          ]),
        );
        evidence.self_test_input = JSON.parse(
          await runCli([
            "self-test",
            "run",
            "--suite",
            "input",
            "--profile",
            "genshin",
            "--test-only",
            "--allow-input",
          ]),
        );
      }
    }
    if (runtimeStarted) {
      evidence.runtime_stop = JSON.parse(await runCli(["runtime", "stop", "--test-only", "--json"]));
      runtimeStarted = false;
    }
    evidence.ok = ok;
    evidence.message = message;
    evidence.saw_hello = sawHello;
    evidence.saw_heartbeat = sawHeartbeat;
    server.close();
    if (ok) {
      process.stdout.write(`${JSON.stringify(evidence)}\n`);
      process.exit(0);
    }
  } catch (cleanupError) {
    message = `${message}; cleanup failed: ${cleanupError.message}`;
  }
  console.error(`smoke failed: ${message}`);
  process.exit(1);
}

function scheduleLogCheck() {
  if (!sawHello || !sawHeartbeat || !runtimeStarted || logCheckScheduled) return;
  logCheckScheduled = true;
  const started = Date.now();
  const checkLog = () => {
    const hasLog =
      fs.existsSync(logPath) && fs.readFileSync(logPath, "utf8").includes("FairyPam Agent starting");
    if (hasLog) {
      void finish(true, "CLI runtime, agent hello, heartbeat, metrics, and logs observed");
    } else if (Date.now() - started > 3000) {
      void finish(false, "agent hello and heartbeat observed, but log file was missing");
    } else {
      setTimeout(checkLog, 150);
    }
  };
  checkLog();
}

const server = net.createServer((socket) => {
  let handshaken = false;
  let pending = Buffer.alloc(0);

  socket.on("data", (chunk) => {
    pending = Buffer.concat([pending, chunk]);

    if (!handshaken) {
      const text = pending.toString("utf8");
      const end = text.indexOf("\r\n\r\n");
      if (end === -1) return;

      const keyLine = text
        .split("\r\n")
        .find((line) => line.toLowerCase().startsWith("sec-websocket-key:"));
      if (!keyLine) {
        void finish(false, "missing websocket key");
        return;
      }

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
        ].join("\r\n")
      );

      handshaken = true;
      pending = pending.subarray(Buffer.byteLength(text.slice(0, end + 4)));
    }

    pending = parseFrames(pending, (opcode, payload) => {
      if (opcode === 0x1) {
        const msg = JSON.parse(payload.toString("utf8"));
        if (msg.type === "agent_hello") {
          sawHello = true;
          socket.write(
            encodeFrame(
              0x1,
              JSON.stringify({
                type: "hub_welcome",
                protocol_version: 3,
                agent_id: "smoke-agent-id",
                agent_name_effective: "smoke-agent",
                config: {
                  heartbeat_interval_s: 1,
                  command_timeout_s: 5,
                  auto_update: false,
                  auto_start: false,
                  launch_allowlist: [],
                },
                accepted_capabilities: msg.capabilities || [],
              })
            )
          );
        }
        if (msg.type === "heartbeat") {
          sawHeartbeat = true;
        }
      } else if (opcode === 0x8) {
        socket.end();
      }

      scheduleLogCheck();
    });
  });
});

server.listen(port, "127.0.0.1", async () => {
  try {
    const status = JSON.parse(await runCli(["status", "--json"]));
    const configValidation = await runCli(["config", "validate"]);
    const start = JSON.parse(await startRuntimeCli());
    evidence.status = status;
    evidence.config_validation = configValidation;
    evidence.runtime_start = start;
    runtimeStarted = true;
    scheduleLogCheck();
  } catch (error) {
    void finish(false, error.message);
  }
});

const timeout = setTimeout(() => {
  void finish(
    false,
    `timeout; sawHello=${sawHello} sawHeartbeat=${sawHeartbeat} runtimeStarted=${runtimeStarted} logCheckScheduled=${logCheckScheduled}`,
  );
}, 30000);
