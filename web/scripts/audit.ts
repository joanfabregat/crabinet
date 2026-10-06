// npm audit with the same release-age rule that .npmrc applies to installs.
//
// `min-release-age` keeps npm from resolving a version until it is a few days
// old, but `npm audit` reports an advisory the moment it is published. A fix
// released yesterday is then reported as missing while npm refuses to install
// it. This wrapper fails only on advisories that have no fix, or whose fix is
// old enough to install; an advisory whose every fix is still too new is a
// warning that names the date the fix becomes installable.
//
// Usage: node scripts/audit.ts [--audit-level=low|moderate|high|critical]

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const SEVERITIES = ["info", "low", "moderate", "high", "critical"];
const DAY_MS = 24 * 60 * 60 * 1000;

interface Advisory {
  name: string;
  title: string;
  url: string;
  severity: string;
}

type Verdict =
  | { kind: "blocking"; reason: string }
  | { kind: "waiting"; installableAt: Date; versions: string[] };

function auditLevel(): string {
  const arg = process.argv.find((a) => a.startsWith("--audit-level="));
  const level = arg ? arg.slice("--audit-level=".length) : "high";
  if (!SEVERITIES.includes(level)) {
    throw new Error(`unknown audit level ${level}`);
  }
  return level;
}

function minReleaseAgeDays(): number {
  const npmrc = readFileSync(".npmrc", "utf8");
  const match = /^\s*min-release-age\s*=\s*(\d+)\s*$/m.exec(npmrc);
  return match ? Number(match[1]) : 0;
}

function advisories(level: string): Advisory[] {
  const result = spawnSync("npm", ["audit", "--json"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const report = JSON.parse(result.stdout);
  if (report.error) {
    throw new Error(`npm audit failed: ${JSON.stringify(report.error)}`);
  }
  const minimum = SEVERITIES.indexOf(level);
  const found = new Map<string, Advisory>();
  for (const vulnerability of Object.values(report.vulnerabilities ?? {})) {
    for (const via of (vulnerability as { via: unknown[] }).via) {
      if (typeof via !== "object" || via === null) continue;
      const advisory = via as Advisory;
      if (SEVERITIES.indexOf(advisory.severity) < minimum) continue;
      found.set(`${advisory.url} ${advisory.name}`, advisory);
    }
  }
  return [...found.values()];
}

async function fetchJson(url: string, headers: Record<string, string> = {}) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`${url} answered ${response.status}`);
  }
  return response.json();
}

async function patchedVersions(advisory: Advisory): Promise<string[] | null> {
  const id = advisory.url.split("/").pop() ?? "";
  if (!/^GHSA(-[0-9a-z]{4}){3}$/.test(id)) return null;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  const details = await fetchJson(
    `https://api.github.com/advisories/${id}`,
    headers,
  );
  const ranges = (details.vulnerabilities ?? []).filter(
    (v: { package?: { ecosystem?: string; name?: string } }) =>
      v.package?.ecosystem === "npm" && v.package?.name === advisory.name,
  );
  const versions = ranges.map(
    (v: { first_patched_version?: string | null }) => v.first_patched_version,
  );
  if (versions.length === 0 || versions.some((v: unknown) => !v)) return null;
  return versions;
}

async function verdict(advisory: Advisory, minDays: number): Promise<Verdict> {
  const versions = await patchedVersions(advisory);
  if (!versions) return { kind: "blocking", reason: "no patched version" };
  const packument = await fetchJson(
    `https://registry.npmjs.org/${advisory.name.replace("/", "%2f")}`,
  );
  const now = Date.now();
  let earliest = Infinity;
  for (const version of versions) {
    const published = Date.parse(packument.time?.[version] ?? "");
    if (Number.isNaN(published)) {
      return { kind: "blocking", reason: `${version} is not on the registry` };
    }
    const installableAt = published + minDays * DAY_MS;
    if (installableAt <= now) {
      return { kind: "blocking", reason: `fixed in ${version}` };
    }
    earliest = Math.min(earliest, installableAt);
  }
  return { kind: "waiting", installableAt: new Date(earliest), versions };
}

function report(kind: "error" | "warning", message: string) {
  if (process.env.GITHUB_ACTIONS === "true") {
    console.log(`::${kind}::${message}`);
  } else {
    console.log(`${kind}: ${message}`);
  }
}

const level = auditLevel();
const minDays = minReleaseAgeDays();
let blocking = 0;
for (const advisory of advisories(level)) {
  const label = `${advisory.severity} ${advisory.name}: ${advisory.title} (${advisory.url})`;
  const result = await verdict(advisory, minDays);
  if (result.kind === "blocking") {
    blocking += 1;
    report("error", `${label}: ${result.reason}`);
  } else {
    report(
      "warning",
      `${label}: fixed in ${result.versions.join(", ")}, installable under min-release-age=${minDays} from ${result.installableAt.toISOString()}`,
    );
  }
}
if (blocking > 0) {
  console.log(`${blocking} advisory finding(s) at ${level} or above`);
  process.exit(1);
}
console.log(`No blocking advisory at ${level} or above`);
