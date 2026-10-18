import { z } from "/p/the8020/db/fields.ts";
import { resolveChallenge } from "../../src/challenges.ts";

export default async function challenge(
  name: string,
  kind: string,
  token: string,
  localOnly = false,
) {
  const parsed = z.tuple([
    z.string().max(255),
    z.enum(["acme", "probe"]),
    z.string().max(256),
    z.boolean(),
  ]).parse([name, kind, token, localOnly]);
  return await resolveChallenge(...parsed) ?? null;
}
