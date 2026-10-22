// Refreshes the initial copies of the auto lists from itdoginfo/allow-domains
// in package/rules. sing-box loads them before its first download, so the VPN
// starts even when GitHub is unreachable.
// Run before a release: node scripts/update-lists.mjs

import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const release = "https://github.com/itdoginfo/allow-domains/releases/latest/download/";

const lists = [
  { tag: "itdog-inside", srs: "russia_inside.srs" },
  { tag: "itdog-google-ai", srs: "google_ai.srs" },
];

for (const l of lists) {
  const res = await fetch(release + l.srs);
  if (!res.ok) throw new Error(`${l.srs}: HTTP ${res.status}`);
  const srs = Buffer.from(await res.arrayBuffer());
  await writeFile(join(root, "package", "rules", `${l.tag}.srs`), srs);
  console.log(`${l.tag}: ${srs.length} bytes`);
}
