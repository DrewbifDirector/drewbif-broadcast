// DrewBif Broadcast — one endpoint for Slack #general → portal.
//   GET  /.netlify/functions/broadcast        -> latest feed (JSON, CORS-open) for Portal Plus
//   POST (from Slack Events API)              -> classify a #general message, store it
//
// Markers (set by whoever posts in #general):
//   starts with "ANNOUNCEMENT"  -> announcement (banner + news list)
//   contains 💩                 -> bad review   (red "needs attention")
//   contains ⭐ / 🌟            -> good review  (gold celebratory)
//   anything else               -> ignored
//
// Env vars required on the Netlify site:
//   SLACK_SIGNING_SECRET   - from the Slack app's Basic Information
//   GENERAL_CHANNEL_ID     - the #general channel ID (e.g. C7VC3TLBE)
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const MAX_ITEMS = 60;
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "content-type" };

function classify(text) {
  const t = (text || "").trim();
  if (/^announcement\b[:\s-]*/i.test(t)) {
    return { type: "announcement", text: t.replace(/^announcement\b[:\s-]*/i, "").trim() || t };
  }
  if (/💩/.test(t)) return { type: "review", sentiment: "bad", stars: 0, text: t };
  const stars = (t.match(/⭐|🌟/g) || []).length;
  if (stars > 0) return { type: "review", sentiment: "good", stars, text: t };
  return null; // ordinary chatter — ignore
}

function verifySlack(signingSecret, headers, rawBody) {
  const ts = headers["x-slack-request-timestamp"];
  const sig = headers["x-slack-signature"];
  if (!ts || !sig) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false; // replay guard (5 min)
  const base = "v0:" + ts + ":" + rawBody;
  const mine = "v0=" + crypto.createHmac("sha256", signingSecret).update(base).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(mine), Buffer.from(sig)); } catch (e) { return false; }
}

export default async (req) => {
  if (req.method === "OPTIONS") return new Response("", { status: 204, headers: CORS });

  const store = getStore("broadcast");

  if (req.method === "GET") {
    const items = (await store.get("items", { type: "json" })) || [];
    return new Response(JSON.stringify({ items }), { status: 200, headers: { ...CORS, "content-type": "application/json", "cache-control": "no-store" } });
  }

  if (req.method === "POST") {
    const raw = await req.text();
    const h = Object.fromEntries(req.headers);
    const secret = process.env.SLACK_SIGNING_SECRET || "";
    if (!secret || !verifySlack(secret, h, raw)) return new Response("bad signature", { status: 401 });

    let body = {};
    try { body = JSON.parse(raw); } catch (e) { return new Response("bad json", { status: 400 }); }

    // Slack URL verification handshake
    if (body.type === "url_verification") {
      return new Response(JSON.stringify({ challenge: body.challenge }), { status: 200, headers: { "content-type": "application/json" } });
    }

    if (body.type === "event_callback" && body.event) {
      const e = body.event;
      const okChannel = !process.env.GENERAL_CHANNEL_ID || e.channel === process.env.GENERAL_CHANNEL_ID;
      const isPlainMessage = e.type === "message" && !e.subtype && !e.bot_id && e.text;
      if (okChannel && isPlainMessage) {
        const cls = classify(e.text);
        if (cls) {
          const items = (await store.get("items", { type: "json" })) || [];
          const id = (e.client_msg_id || e.ts || String(Date.now()));
          if (!items.some((x) => x.id === id)) { // idempotent against Slack retries
            items.unshift({ id, ts: Number(e.ts ? e.ts * 1000 : Date.now()), ...cls });
            await store.setJSON("items", items.slice(0, MAX_ITEMS));
          }
        }
      }
    }
    // Always 200 fast so Slack doesn't retry.
    return new Response("ok", { status: 200 });
  }

  return new Response("method not allowed", { status: 405, headers: CORS });
};
