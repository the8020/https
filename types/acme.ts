import { z } from "/p/the8020/db/fields.ts";
import { secretName } from "/p/the8020/secrets/types/secret.ts";

export const acmeOrder = z.object({
  url: z.url().max(2048),
  status: z.enum(["pending", "ready", "processing", "valid", "invalid"]),
  identifiers: z.array(
    z.object({ type: z.string(), value: z.string().max(253) }),
  ).max(100),
  authorizations: z.array(z.url().max(2048)).max(100),
  finalize: z.url().max(2048),
  expires: z.string().optional(),
  certificate: z.url().max(2048).optional(),
});

export const orderState = z.object({
  directory: z.url().max(2048),
  keySecret: secretName.min(1),
  csr: z.string().max(65536),
  order: acmeOrder.nullable(),
});
export type OrderState = z.infer<typeof orderState>;
