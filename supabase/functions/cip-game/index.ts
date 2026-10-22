
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

async function verifyTelegram(initData: string, botToken: string) {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  const authDate = Number(params.get("auth_date"));

  if (!hash || !authDate) return null;

  const now = Math.floor(Date.now() / 1000);
  if (now - authDate > 86400 || authDate > now + 60) return null;

  const entries = [...params.entries()]
    .filter(([key]) => key !== "hash")
    .sort(([a], [b]) => a.localeCompare(b));

  const checkString = entries.map(([k, v]) => `${k}=${v}`).join("\n");

  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode("WebAppData"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const secret = await crypto.subtle.sign(
    "HMAC",
    keyMaterial,
    encoder.encode(botToken),
  );

  const hmacKey = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    hmacKey,
    encoder.encode(checkString),
  );

  const calculatedHash = [...new Uint8Array(signature)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  if (calculatedHash !== hash.toLowerCase()) return null;

  try {
    return JSON.parse(params.get("user") || "null");
  } catch {
    return null;
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  if (req.method !== "POST") {
    return json({ error: "POST required" }, 405);
  }

  try {
    const botToken = Deno.env.get("TELEGRAM_BOT_TOKEN");
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!botToken || !supabaseUrl || !serviceKey) {
      return json({ error: "Server configuration missing" }, 500);
    }

    const body = await req.json();
    const user = await verifyTelegram(body.initData || "", botToken);

    if (!user?.id) {
      return json({ error: "Telegram verification failed" }, 401);
    }

    const db = createClient(supabaseUrl, serviceKey);
    const telegramId = String(user.id);

    const { error: profileError } = await db
      .from("cip_profiles")
      .upsert({
        telegram_id: telegramId,
        first_name: user.first_name || null,
        last_name: user.last_name || null,
        display_name: [user.first_name, user.last_name]
          .filter(Boolean).join(" ") || null,
        updated_at: new Date().toISOString(),
      }, { onConflict: "telegram_id" });

    if (profileError) throw profileError;

    const { error: stateError } = await db
      .from("cip_player_state")
      .upsert({
        telegram_id: telegramId,
      }, { onConflict: "telegram_id", ignoreDuplicates: true });

    if (stateError) throw stateError;

    const { data: state, error } = await db
      .from("cip_player_state")
      .select("*")
      .eq("telegram_id", telegramId)
      .single();

    if (error) throw error;

    return json({
      ok: true,
      player: {
        telegram_id: telegramId,
        name: [user.first_name, user.last_name]
          .filter(Boolean).join(" "),
      },
      state,
      server_time: new Date().toISOString(),
    });
  } catch (err) {
    console.error(err);
    return json({ error: "Server error" }, 500);
  }
});
