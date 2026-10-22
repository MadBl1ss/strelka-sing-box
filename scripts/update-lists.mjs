// Refreshes the auto lists from itdoginfo/allow-domains:
//   package/rules/*.srs  initial copies sing-box loads before its first download
//   site/data/*.txt      plain domain lists the site uses for its checker
// Run before a release: node scripts/update-lists.mjs

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const release = "https://github.com/itdoginfo/allow-domains/releases/latest/download/";
const raw = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/";

const lists = [
  { tag: "itdog-inside", srs: "russia_inside.srs", txt: "Russia/inside-raw.lst" },
  { tag: "itdog-google-ai", srs: "google_ai.srs", txt: "Services/google_ai.lst" },
];

async function fetchOk(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res;
}

for (const l of lists) {
  const srs = Buffer.from(await (await fetchOk(release + l.srs)).arrayBuffer());
  const srsPath = join(root, "package", "rules", `${l.tag}.srs`);
  await writeFile(srsPath, srs);

  const domains = (await (await fetchOk(raw + l.txt)).text())
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith("#"));
  const txtPath = join(root, "site", "data", `${l.tag}.txt`);
  await mkdir(dirname(txtPath), { recursive: true });
  await writeFile(txtPath, domains.join("\n") + "\n");

  console.log(`${l.tag}: ${srs.length} bytes srs, ${domains.length} domains`);
}
