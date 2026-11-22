/**
 * Joy Guru — Razorpay Edge Function
 * Handles: POST /create-order  →  creates a Razorpay order
 *          POST /verify        →  verifies payment signature (no money moves without this)
 *
 * Secrets required (Supabase Dashboard → Settings → Edge Functions → Secrets):
 *   RAZORPAY_KEY_ID      your rzp_live_... key
 *   RAZORPAY_KEY_SECRET  your secret key (NEVER in frontend)
 *
 * Deploy:
 *   supabase functions deploy razorpay --no-verify-jwt
 *
 * Backend URL to put in Joy Guru Settings:
 *   https://<your-project-ref>.supabase.co/functions/v1/razorpay
 */

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import {
  createHmac,
} from "https://deno.land/std@0.168.0/node/crypto.ts";

// ── CORS headers ─────────────────────────────────────────────────────────────
// The frontend at offline.joygurushop.in calls this function directly from the
// browser, so we must respond to preflight OPTIONS requests.
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function corsResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

// ── Razorpay helpers ──────────────────────────────────────────────────────────
function razorpayAuthHeader(): string {
  const keyId     = Deno.env.get("RAZORPAY_KEY_ID")!;
  const keySecret = Deno.env.get("RAZORPAY_KEY_SECRET")!;
  return "Basic " + btoa(`${keyId}:${keySecret}`);
}

// ── Handler ───────────────────────────────────────────────────────────────────
serve(async (req: Request) => {
  // Preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS });
  }

  if (req.method !== "POST") {
    return corsResponse({ error: "Method not allowed" }, 405);
  }

  const url  = new URL(req.url);
  const path = url.pathname; // e.g. /functions/v1/razorpay/create-order

  // ── POST /create-order ──────────────────────────────────────────────────────
  // Frontend sends: { amount: <paise>, currency: "INR", receipt: "joy-..." }
  // We call Razorpay API and return the full order object (contains id = order_id)
  if (path.endsWith("/create-order")) {
    let body: { amount: number; currency?: string; receipt?: string };
    try {
      body = await req.json();
    } catch {
      return corsResponse({ error: "Invalid JSON body" }, 400);
    }

    if (!body.amount || body.amount <= 0) {
      return corsResponse({ error: "amount is required and must be > 0" }, 400);
    }

    const rzpRes = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": razorpayAuthHeader(),
      },
      body: JSON.stringify({
        amount:   Math.round(body.amount),          // already in paise from frontend
        currency: body.currency ?? "INR",
        receipt:  body.receipt  ?? `joy-${Date.now()}`,
      }),
    });

    const rzpData = await rzpRes.json();

    if (!rzpRes.ok) {
      console.error("Razorpay create-order error:", rzpData);
      return corsResponse(
        { error: rzpData?.error?.description ?? "Failed to create order" },
        rzpRes.status,
      );
    }

    return corsResponse(rzpData);
  }

  // ── POST /verify ────────────────────────────────────────────────────────────
  // Frontend sends: { razorpay_order_id, razorpay_payment_id, razorpay_signature }
  // We verify HMAC-SHA256(order_id|payment_id, key_secret) === signature
  // NO money moves here — this just confirms the payment wasn't tampered with.
  if (path.endsWith("/verify")) {
    let body: {
      razorpay_order_id:   string;
      razorpay_payment_id: string;
      razorpay_signature:  string;
    };
    try {
      body = await req.json();
    } catch {
      return corsResponse({ error: "Invalid JSON body" }, 400);
    }

    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return corsResponse({ error: "Missing required fields" }, 400);
    }

    const keySecret = Deno.env.get("RAZORPAY_KEY_SECRET")!;
    const message   = `${razorpay_order_id}|${razorpay_payment_id}`;
    const expected  = createHmac("sha256", keySecret)
      .update(message)
      .digest("hex");

    if (expected !== razorpay_signature) {
      console.warn("Signature mismatch — possible tampering", {
        razorpay_order_id,
        razorpay_payment_id,
      });
      return corsResponse({ ok: false, error: "Invalid payment signature" }, 400);
    }

    return corsResponse({ ok: true, paymentId: razorpay_payment_id });
  }

  return corsResponse({ error: "Unknown endpoint" }, 404);
});
