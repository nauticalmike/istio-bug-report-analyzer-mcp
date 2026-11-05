import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/server.js";

async function instructionsFor(soloMode: boolean): Promise<string | undefined> {
  const { server } = createServer({ soloMode });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const instructions = client.getInstructions();
  await client.close();
  return instructions;
}

describe("solo mode", () => {
  it("points the session at the Solo-internal plugins when SOLO_MODE is on", async () => {
    const text = await instructionsFor(true);
    for (const plugin of ["Customer360", "Solo knowledge base", "Support agent", "Migration assessment"]) expect(text).toContain(plugin);
  });

  it("sends no instructions otherwise", async () => {
    expect(await instructionsFor(false)).toBeUndefined();
  });
});
