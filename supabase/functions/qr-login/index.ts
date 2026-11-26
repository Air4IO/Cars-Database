import { createAccessToken, corsHeaders, jsonResponse, serviceClient } from "../_shared/auth.ts";

async function tokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return jsonResponse({ detail: "ไม่รองรับคำขอนี้" }, 405);

  try {
    const body = await req.json();
    const token = String(body.token || "").trim();
    if (!/^[A-Za-z0-9_-]{40,50}$/.test(token)) {
      return jsonResponse({ detail: "QR นี้ไม่ถูกต้องหรือถูกปิดไปแล้ว" }, 401);
    }

    const db = serviceClient();
    const { data: qr, error: qrError } = await db.from("app_user_qr_access")
      .select("user_id")
      .eq("token_hash", await tokenHash(token))
      .is("revoked_at", null)
      .maybeSingle();
    if (qrError) throw qrError;
    if (!qr) return jsonResponse({ detail: "QR นี้ไม่ถูกต้องหรือถูกปิดไปแล้ว" }, 401);

    const { data: user, error: userError } = await db.from("app_users")
      .select("id,username,role,allowed_brands,active")
      .eq("id", qr.user_id)
      .maybeSingle();
    if (userError) throw userError;
    if (!user || !user.active || user.role !== "user") {
      return jsonResponse({ detail: "บัญชีนี้ถูกปิดใช้งานแล้ว" }, 403);
    }

    const { error: useError } = await db.from("app_user_qr_access")
      .update({ last_used_at: new Date().toISOString() })
      .eq("user_id", user.id)
      .eq("token_hash", await tokenHash(token))
      .is("revoked_at", null);
    if (useError) throw useError;

    return jsonResponse({
      access_token: await createAccessToken(user.username),
      token_type: "bearer",
      expires_in_hours: Number(Deno.env.get("TOKEN_EXPIRE_HOURS") || "12"),
      user: {
        username: user.username,
        role: user.role,
        allowed_brands: user.allowed_brands || [],
      },
    });
  } catch (error) {
    console.error("QR login error:", error);
    return jsonResponse({ detail: "เข้าสู่ระบบด้วย QR ไม่สำเร็จ กรุณาลองใหม่" }, 500);
  }
});

