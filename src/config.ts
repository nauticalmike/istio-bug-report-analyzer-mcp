import type { ServerConfig } from "./types.js";

export function loadConfig(): ServerConfig {
  return {
    soloMode: process.env.SOLO_MODE === "true",
  };
}
