import {
  BACK_EVENT,
  callScreen,
  fileUpload,
  Model,
  presentModal,
  presentPage,
  sendMessage,
  z,
} from "/p/the8020/uui/mod.ts";
import { certificateRecords } from "../../src/admin.ts";
import { uploadCertificate } from "../../src/certificates.ts";
import { applyChanges } from "../../src/configuration.ts";
import {
  certificateFiles,
  certificateRecord,
} from "../../types/certificate.ts";
import issue from "../issue/program.ts";
import { savedMessage, showError } from "./program.ts";

export async function certificates(): Promise<void> {
  const schema = z.object({ certificates: z.array(certificateRecord) });
  const model = new Model<z.infer<typeof schema>>({ certificates: [] });
  while (true) {
    model.data.certificates = await certificateRecords();
    const event = await callScreen({
      id: "https-certificates",
      title: "HTTPS certificates",
      schema,
      model,
      layout: {
        schema: 1,
        id: "https-certificates",
        root: {
          type: "list",
          bind: "certificates",
          key: "name",
          display: ["name", "coveredNames", "source", "expiresAt", "status"],
        },
      },
      header: {
        actions: [
          { id: "upload", label: "Upload certificate", kind: "primary" },
          { id: "refresh", label: "Refresh" },
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "upload") await presentModal(() => upload());
      if (event.action === "select" && typeof event.value === "string") {
        await presentPage(() => detail(String(event.value)));
      }
    } catch (error) {
      showError(error);
    }
  }
}

async function upload(name = ""): Promise<void> {
  const schema = certificateFiles;
  const model = new Model({ name, chain: "", key: "" });
  while (true) {
    model.data.chain = model.data.key = "";
    const chain = fileUpload({
      maximumBytes: 262144,
      accept: ".pem,.crt,.cer",
    });
    const key = fileUpload({ maximumBytes: 65536, accept: ".pem,.key" });
    const event = await callScreen({
      id: "https-upload",
      title: name ? "Replace certificate" : "Upload certificate",
      schema,
      model,
      controls: [
        { id: "name", bind: "name", readOnly: name !== "", length: "long" },
        {
          id: "chain",
          bind: "chain",
          custom: chain.custom,
          fieldHelp: false,
          length: "long",
        },
        {
          id: "key",
          bind: "key",
          custom: key.custom,
          fieldHelp: false,
          length: "long",
        },
      ],
      header: { actions: [{ id: "save", label: "Save", kind: "primary" }] },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action !== "save") continue;
    try {
      const decoder = new TextDecoder("utf-8", { fatal: true });
      await uploadCertificate(
        model.data.name,
        decoder.decode(chain.take()),
        decoder.decode(key.take()),
      );
      savedMessage(await applyChanges());
      return;
    } catch (error) {
      showError(error);
    }
  }
}

async function detail(name: string): Promise<void> {
  let model: Model<z.infer<typeof certificateRecord>> | undefined;
  while (true) {
    const record = (await certificateRecords(name))[0];
    if (!record) throw new Error("Certificate no longer exists");
    model ??= new Model(record);
    model.data = record;
    const common = [
      "name",
      "coveredNames",
      "source",
      "status",
      "expiresAt",
      "lastError",
    ];
    const event = await callScreen({
      id: "https-certificate",
      title: name,
      schema: certificateRecord,
      model,
      controls: common.map((key) => ({
        id: key,
        bind: key,
        readOnly: true,
        length: "long" as const,
      })),
      header: {
        actions: [
          { id: "upload", label: "Replace certificate" },
          ...(record.source !== "provided"
            ? [{ id: "renew", label: record.lastError ? "Retry" : "Renew" }]
            : []),
          { id: "advanced", label: "Advanced" },
          { id: "refresh", label: "Refresh" },
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "upload") await presentModal(() => upload(name));
      if (event.action === "renew") {
        const result = await issue(name, "renew");
        if (result.status === "busy") {
          sendMessage("A certificate operation is already running", "info");
        } else savedMessage(result);
      }
      if (event.action === "advanced") {
        await presentModal(() =>
          callScreen({
            id: "https-certificate-advanced",
            title: "Certificate details",
            schema: certificateRecord,
            model: new Model(record),
            controls: [
              "fingerprint",
              "validFrom",
              "expiresAt",
              "dueAt",
              "claimUntil",
              "lastError",
            ].map((key) => ({
              id: key,
              bind: key,
              readOnly: true,
              length: "long" as const,
            })),
          })
        );
      }
    } catch (error) {
      showError(error);
    }
  }
}
