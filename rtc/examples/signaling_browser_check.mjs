// Independent real Chrome peer. Grounds packet/state decisions remain in Bend.
// Run with Bun: signaling_browser_check.mjs <evidence-dir> <server-command...>.
import {spawn} from "node:child_process";
import {mkdtemp, readFile, mkdir, writeFile, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";

const [evidenceArg, ...command] = process.argv.slice(2);
if (!evidenceArg || !command.length) throw new Error("expected evidence directory and server command");
const evidence = resolve(evidenceArg);
await mkdir(evidence, {recursive: true});
const profile = await mkdtemp(join(tmpdir(), "grounds-ice-chrome-"));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const until = async (run, ms = 10000) => {
  const end = performance.now() + ms;
  let error;
  while (performance.now() < end) {
    try { const value = await run(); if (value) return value; } catch (e) { error = e; }
    await delay(50);
  }
  throw new Error(`deadline expired: ${error || "condition not met"}`);
};

class CDP {
  constructor(ws) {
    this.ws = ws; this.serial = 0; this.pending = new Map();
    ws.addEventListener("message", event => {
      const value = JSON.parse(event.data);
      if (!value.id) return;
      const promise = this.pending.get(value.id);
      if (!promise) return;
      this.pending.delete(value.id);
      value.error ? promise.reject(new Error(JSON.stringify(value.error))) : promise.resolve(value.result);
    });
  }
  async send(method, params = {}) {
    const id = ++this.serial;
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 20000);
      this.pending.set(id, {resolve: value => {clearTimeout(timer); resolve(value);}, reject: error => {clearTimeout(timer); reject(error);}});
      this.ws.send(JSON.stringify({id, method, params}));
    });
  }
  async evaluate(expression) {
    const value = await this.send("Runtime.evaluate", {expression, awaitPromise: true, returnByValue: true});
    if (value.exceptionDetails) throw new Error(JSON.stringify(value.exceptionDetails));
    return value.result.value;
  }
}

let server, chrome, cdpSocket;
let serverLog = "", serverError = "", chromeError = "";
const results = {scope: "plaintext local WS + ICE only; no DTLS/data/media proof", command, rounds: []};
const stop = async child => {
  if (!child) return null;
  if (child.exitCode !== null || child.signalCode !== null) return {code: child.exitCode, signal: child.signalCode, forced: false};
  child.kill("SIGTERM");
  await Promise.race([new Promise(resolve => child.once("exit", resolve)), delay(5000)]);
  const forced = child.exitCode === null && child.signalCode === null;
  if (forced) {
    child.kill("SIGKILL");
    await Promise.race([new Promise(resolve => child.once("exit", resolve)), delay(3000)]);
  }
  return {code: child.exitCode, signal: child.signalCode, forced};
};
try {
  // Refuse to use another process's listener as evidence.
  try { await fetch("http://127.0.0.1:8089/"); throw new Error("fixture port 8089 already occupied"); }
  catch (e) { if (String(e).includes("already occupied")) throw e; }
  server = spawn(command[0], command.slice(1), {stdio: ["ignore", "pipe", "pipe"]});
  server.stdout.on("data", data => { serverLog += data; });
  server.stderr.on("data", data => { serverError += data; });
  await until(async () => { if (server.exitCode !== null) throw new Error(`server exited ${server.exitCode}: ${serverError}`); return (await fetch("http://127.0.0.1:8089/")).ok; });
  const chromePath = process.env.GROUNDS_CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  const extraFlags = JSON.parse(process.env.GROUNDS_CHROME_FLAGS || "[]");
  if (!Array.isArray(extraFlags) || extraFlags.some(value => typeof value !== "string")) throw new Error("GROUNDS_CHROME_FLAGS must be a JSON string array");
  const disabledFeatures = new Set(["WebRtcHideLocalIpsWithMdns"]);
  const otherFlags = extraFlags.filter(flag => {
    if (!flag.startsWith("--disable-features=")) return true;
    for (const feature of flag.slice("--disable-features=".length).split(",")) if (feature) disabledFeatures.add(feature);
    return false;
  });
  const chromeArguments = ["--headless=new", "--no-first-run", "--no-default-browser-check", "--remote-debugging-port=0",
    `--user-data-dir=${profile}`, `--disable-features=${[...disabledFeatures].join(",")}`, ...otherFlags, "about:blank"];
  results.chromeArguments = chromeArguments;
  // Preserve launch attribution even when the resource guard stops the tree
  // before this process's finally block can run.
  await writeFile(join(evidence, "launch.json"), JSON.stringify({command, chromePath, chromeArguments, profile}, null, 2));
  chrome = spawn(chromePath, chromeArguments, {stdio: ["ignore", "ignore", "pipe"]});
  chrome.stderr.on("data", data => { chromeError += data; });
  const port = await until(async () => (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0]);
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const target = targets.find(value => value.type === "page");
  if (!target) throw new Error("no isolated Chrome page");
  cdpSocket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { cdpSocket.addEventListener("open", resolve, {once: true}); cdpSocket.addEventListener("error", reject, {once: true}); });
  const cdp = new CDP(cdpSocket);
  results.browser = await cdp.send("Browser.getVersion");
  results.initialTargets = (await cdp.send("Target.getTargets")).targetInfos;
  await writeFile(join(evidence, "startup.json"), JSON.stringify({browser: results.browser, targets: results.initialTargets}, null, 2));
  await cdp.send("Page.enable");
  await cdp.send("Page.navigate", {url: "http://127.0.0.1:8089/"});
  await until(async () => (await cdp.evaluate("location.origin")) === "http://127.0.0.1:8089");
  const denied = async () => await cdp.evaluate(`(async () => {
    const ws = new WebSocket('ws://127.0.0.1:8089/signal');
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {ws.close(); reject(new Error('denial deadline'));}, 5000);
      let failed = false;
      ws.onerror = () => { failed = true; };
      ws.onopen = () => {clearTimeout(timer); ws.close(); reject(new Error('unauthorized WS opened'));};
      ws.onclose = event => {clearTimeout(timer); resolve({failed, code: event.code});};
    });
  })()`);
  results.deniedAuth = await denied();
  if (!results.deniedAuth.failed || serverLog.includes("signaling-base:")) throw new Error("failed auth allocated a UDP base");
  await cdp.send("Page.navigate", {url: "http://localhost:8089/"});
  await until(async () => (await cdp.evaluate("location.origin")) === "http://localhost:8089");
  results.deniedOrigin = await denied();
  if (!results.deniedOrigin.failed || serverLog.includes("signaling-base:")) throw new Error("denied Origin allocated a UDP base");
  await cdp.send("Page.navigate", {url: "http://127.0.0.1:8089/"});
  await until(async () => (await cdp.evaluate("location.origin")) === "http://127.0.0.1:8089");
  const issuedCookie = await until(() => Promise.resolve(serverLog.match(/^signaling-cookie:([^\n]+)$/m)?.[1]));
  results.cookieSource = "Bend minted synthetic session cookie";
  await cdp.evaluate(`(async () => {
    document.cookie = ${JSON.stringify(issuedCookie + '; SameSite=Strict; Path=/')};
    window.grounds = {pc: new RTCPeerConnection({iceServers: []}), ws: new WebSocket('ws://127.0.0.1:8089/signal'), messages: [], states: []};
    grounds.dc = grounds.pc.createDataChannel('ICE-fixture-only');
    grounds.pc.oniceconnectionstatechange = () => grounds.states.push({at: performance.now(), ice: grounds.pc.iceConnectionState});
    grounds.ws.onmessage = event => grounds.messages.push(JSON.parse(event.data));
    await new Promise((resolve, reject) => { grounds.ws.onopen = resolve; grounds.ws.onerror = () => reject(new Error('fixture WS denied')); });
    return true;
  })()`);
  for (const revision of [0, 1]) {
    const result = await cdp.evaluate(`(async () => {
      const revision = ${revision};
      if (revision) grounds.pc.restartIce();
      await grounds.pc.setLocalDescription(await grounds.pc.createOffer({iceRestart: !!revision}));
      if (grounds.pc.iceGatheringState !== 'complete') await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('ICE gathering deadline')), 8000);
        grounds.pc.onicegatheringstatechange = () => { if (grounds.pc.iceGatheringState === 'complete') {clearTimeout(timeout); resolve();} };
      });
      const offer = grounds.pc.localDescription.sdp;
      grounds.ws.send(JSON.stringify(['offer', revision, offer]));
      const answer = await new Promise((resolve, reject) => {
        const end = performance.now() + 5000;
        const poll = () => { const value = grounds.messages.shift(); if (value) return resolve(value); if (performance.now() >= end) return reject(new Error('answer deadline')); setTimeout(poll, 20); }; poll();
      });
      if (answer[0] !== 'answer') throw new Error('wrong signaling reply');
      await grounds.pc.setRemoteDescription({type: 'answer', sdp: answer[1]});
      return {revision, offer, answer: answer[1]};
    })()`);
    await until(() => Promise.resolve(serverLog.includes(`consent-selected:${revision}:`)), 12000);
    // Wait for authenticated one-shot consent, rather than only ICE state flags.
    await until(() => Promise.resolve(new RegExp(`consent-event:${revision}:[^\\n]+\\nrenewed:`).test(serverLog)), 12000);
    result.stats = await cdp.evaluate(`(async () => {
      const stats = [...(await grounds.pc.getStats()).values()];
      const iceTransport = grounds.pc.sctp?.transport.iceTransport;
      const selected = iceTransport?.getSelectedCandidatePair();
      return {ice: grounds.pc.iceConnectionState, connection: grounds.pc.connectionState,
        iceTransport: {state: iceTransport?.state, role: iceTransport?.role,
          selected: selected ? {local: selected.local.toJSON(), remote: selected.remote.toJSON()} : null},
        data: grounds.dc.readyState, states: grounds.states,
        reports: stats.filter(value => ['candidate-pair', 'local-candidate', 'remote-candidate', 'transport'].includes(value.type))};
    })()`);
    results.rounds.push(result);
    if (!result.stats.iceTransport.selected || !['connected', 'completed'].includes(result.stats.iceTransport.state))
      throw new Error("browser lacks an actual selected ICE transport pair");
    if (result.stats.data === "open") throw new Error("unexpected DTLS/data delegation");
  }
  await cdp.evaluate("grounds.pc.close(); grounds.ws.close(); true");
  await until(() => Promise.resolve(serverLog.includes("signaling-closed:")), 5000);
  results.reconnect = await cdp.evaluate(`(async () => {
    const ws = new WebSocket('ws://127.0.0.1:8089/signal');
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('reconnect deadline')), 5000);
      let opened = false;
      ws.onopen = () => {opened = true; ws.close();};
      ws.onerror = () => {clearTimeout(timer); reject(new Error('reconnect failed'));};
      ws.onclose = event => {clearTimeout(timer); resolve({opened, code: event.code});};
    });
  })()`);
  if (!results.reconnect.opened) throw new Error("browser reconnect failed");
  results.malformed = await cdp.evaluate(`(async () => {
    const ws = new WebSocket('ws://127.0.0.1:8089/signal');
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('malformed message deadline')), 5000);
      ws.onopen = () => ws.send(JSON.stringify({offer: 'invalid schema'}));
      ws.onclose = event => {clearTimeout(timer); resolve({code: event.code});};
      ws.onerror = () => {clearTimeout(timer); reject(new Error('malformed fixture handshake failed'));};
    });
  })()`);
  if (results.malformed.code !== 1008) throw new Error("malformed signaling was admitted");
  await until(() => Promise.resolve((serverLog.match(/signaling-base:/g) || []).length ===
    (serverLog.match(/signaling-closed:/g) || []).length), 5000);
  results.passed = true;
  console.log("Chrome: authenticated WS, actual nominated ICE, fresh consent and credential restart passed (DTLS/data/media absent)");
} catch (error) {
  results.passed = false;
  results.error = String(error.stack || error);
  throw error;
} finally {
  cdpSocket?.close();
  results.shutdown = {chrome: await stop(chrome), server: await stop(server)};
  const cleanupFailed = results.passed && (results.shutdown.server.forced || results.shutdown.server.code !== 0);
  if (cleanupFailed) {results.passed = false; results.error = 'Grounds server did not exit cleanly on SIGTERM';}
  await Promise.all([
    writeFile(join(evidence, "browser.json"), JSON.stringify(results, null, 2)),
    writeFile(join(evidence, "server.log"), serverLog),
    writeFile(join(evidence, "server.stderr.log"), serverError),
    writeFile(join(evidence, "chrome.stderr.log"), chromeError),
  ]);
  await rm(profile, {recursive: true, force: true});
  if (cleanupFailed) throw new Error(results.error);
}
