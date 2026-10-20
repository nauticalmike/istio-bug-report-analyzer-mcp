import { readFileSync } from "node:fs";

// package.json sits one level above both src/ and dist/, and ships in the npm tarball.
export const SERVER_VERSION: string = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf-8"),
).version;
