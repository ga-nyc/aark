import { spawnSync } from "node:child_process";

const candidates = process.platform === "win32"
  ? [["py", "-3"], ["python"], ["python3"]]
  : [["python3"], ["python"]];
const code = "import ast,pathlib; [ast.parse(pathlib.Path(p).read_text(encoding='utf-8')) for p in ['optional/impacket/dpapi_bridge.py', 'scripts/notify-local.py', 'scripts/notify-local.test.py', 'scripts/source-dm-digest.py', 'scripts/source-dm-digest.test.py']]";
let found = false;
for (const [command, ...prefix] of candidates) {
  const probe = spawnSync(command, [...prefix, "--version"], { shell: false, windowsHide: true, encoding: "utf8" });
  const version = /^Python (\d+)\.(\d+)/.exec(probe.stdout || probe.stderr || "");
  if (probe.status !== 0 || version === null || Number(version[1]) !== 3 || Number(version[2]) < 7) continue;
  found = true;
  const result = spawnSync(command, [...prefix, "-c", code], { shell: false, windowsHide: true, stdio: "inherit" });
  if (result.status !== 0) process.exitCode = result.status ?? 1;
  else {
    const tests = spawnSync(command, [...prefix, "scripts/notify-local.test.py"], { shell: false, windowsHide: true, stdio: "inherit" });
    process.exitCode = tests.status ?? 1;
    if (process.exitCode === 0) {
      const digestTests = spawnSync(command, [...prefix, "scripts/source-dm-digest.test.py"], { shell: false, windowsHide: true, stdio: "inherit" });
      process.exitCode = digestTests.status ?? 1;
    }
  }
  break;
}
if (!found) {
  process.stderr.write("Python 3.7 or newer is required for check:python (py -3, python3, or python).\n");
  process.exitCode = 1;
}
