import { mkdirSync, writeFileSync } from "node:fs";

// Mark each output directory with its module format so Node loads both builds.
for (const [dir, type] of [
  ["dist/esm", "module"],
  ["dist/cjs", "commonjs"],
]) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}/package.json`, JSON.stringify({ type }) + "\n");
}
