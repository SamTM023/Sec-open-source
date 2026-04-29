import { spawn } from "child_process";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { v4 as uuid } from "uuid";
import { XMLParser } from "fast-xml-parser";

import type { Finding } from "@sec/shared";
import type { ScannerContext } from "../orchestrator";

export async function runNikto(ctx: ScannerContext): Promise<void> {
  validateTarget(ctx.target);

  ctx.log("Nikto initialisatie...");

  const outFile = path.join(
    os.tmpdir(),
    `nikto-${ctx.scanId}-${Date.now()}.xml`
  );

  const wslOutFile = toWSLPath(outFile);
  const distro = "Ubuntu";

  ctx.log(`WSL distro: ${distro}`);
  ctx.log(`Output (WSL): ${wslOutFile}`);

  const cmd = buildNiktoCommand(ctx.target, wslOutFile, ctx.options);

  ctx.log(`Nikto gestart tegen ${ctx.target}`);

  const proc = spawn(
    "wsl",
    [
      "-d",
      distro,
      "--",
      "sh",
      "-c",
      cmd,
    ],
    {
      stdio: ["ignore", "pipe", "pipe"],
    }
  );

  /**
   * Timeout protection (Nikto can hang on slow hosts)
   */
  const timeout = setTimeout(() => {
    ctx.log("Nikto timeout bereikt → proces wordt gestopt");
    proc.kill("SIGKILL");
  }, 10 * 60 * 1000); // 10 min

  proc.stdout.on("data", (chunk) => {
    ctx.log(chunk.toString().trim());
  });

  proc.stderr.on("data", (chunk) => {
    ctx.log(chunk.toString().trim());
  });

  await new Promise<void>((resolve, reject) => {
    proc.on("close", (code) => {
      clearTimeout(timeout);

      if (code === 0 || code === null) {
        resolve();
      } else {
        reject(new Error(`Nikto exited with code ${code}`));
      }
    });

    proc.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });

  ctx.log("Nikto scan voltooid. XML verwerken...");

  const xml = await fs.readFile(outFile, "utf8");

  const findings = parseNiktoXml(xml, ctx.target);

  if (findings.length > 0) {
    ctx.addFindings(findings);
  }

  ctx.log(`Nikto klaar (${findings.length} findings).`);

  await fs.unlink(outFile).catch(() => {});
}

/**
 * Improved scan command (deeper + more complete coverage)
 */
function buildNiktoCommand(
  target: string,
  outFile: string,
  options?: ScannerContext["options"]
): string {
  const parts = [
    `nikto -h "${target}"`,
    `-Format xml`,
    `-output "${outFile}"`,

    // 🔥 deeper scan (important upgrade)
    `-C all`,
  ];

  // SSL support
  if (options?.ssl) {
    parts.push("-ssl");
  }

  // safer tuning handling
  if (options?.tuning) {
    parts.push(`-Tuning ${options.tuning}`);
  }

  return parts.join(" ");
}

/**
 * Windows → WSL path conversion
 */
function toWSLPath(p: string): string {
  const match = p.match(/^([A-Za-z]):\\(.*)$/);

  if (!match) {
    throw new Error(`Ongeldig Windows pad: ${p}`);
  }

  const [, drive, rest] = match;

  return `/mnt/${drive.toLowerCase()}/${rest.replace(/\\/g, "/")}`;
}

/**
 * Parse Nikto XML output
 */
function parseNiktoXml(xml: string, target: string): Finding[] {
  const parser = new XMLParser({
    ignoreAttributes: false,
  });

  const data = parser.parse(xml);

  const items = data?.niktoscan?.scandetails?.item;

  if (!items) return [];

  const list = Array.isArray(items) ? items : [items];

  return list.map((item: any) => ({
    id: uuid(),
    severity: mapSeverity(item.description),
    title: item.description ?? "Nikto finding",
    location: item.uri ? target + item.uri : target,
    description:
      item.namelink ??
      item.references ??
      "Finding gedetecteerd door Nikto.",
  }));
}

/**
 * Severity mapping (slightly improved signal detection)
 */
function mapSeverity(text: string = ""): Finding["severity"] {
  const t = text.toLowerCase();

  if (
    t.includes("sql") ||
    t.includes("xss") ||
    t.includes("rce") ||
    t.includes("remote code") ||
    t.includes("injection")
  ) {
    return "high";
  }

  if (
    t.includes("outdated") ||
    t.includes("admin") ||
    t.includes("directory") ||
    t.includes("exposed")
  ) {
    return "medium";
  }

  if (
    t.includes("header") ||
    t.includes("options") ||
    t.includes("trace") ||
    t.includes("missing")
  ) {
    return "low";
  }

  return "info";
}

/**
 * Target validation
 */
function validateTarget(target: string): void {
  let url: URL;

  try {
    url = new URL(target);
  } catch {
    throw new Error("Ongeldige target URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Alleen HTTP/HTTPS targets toegestaan.");
  }

  const host = url.hostname;

  if (
    host === "localhost" ||
    host.startsWith("127.") ||
    host.startsWith("10.") ||
    host.startsWith("192.168.")
  ) {
    throw new Error("Interne/private targets zijn geblokkeerd.");
  }
}