import {
  corsHeaders,
  getCurrentUser,
  hashPassword,
  jsonResponse,
  requireAdmin,
  serviceClient,
} from "../_shared/auth.ts";

const usernamePattern = /^[a-z0-9][a-z0-9_-]{2,31}$/;

function publicRecord(user: Record<string, unknown>) {
  return {
    username: user.username,
    role: user.role,
    allowed_brands: user.allowed_brands || [],
    active: Boolean(user.active),
    created_at: user.created_at,
    last_login: user.last_login,
  };
}

function cleanBrands(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const values = [...new Set(input.map((item) => String(item).trim()).filter(Boolean))];
  return values.some((item) => item.toUpperCase() === "ALL") ? ["ALL"] : values;
}

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function tokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const admin = await requireAdmin(req);
  if (admin instanceof Response) return admin;

  const db = serviceClient();
  const path = new URL(req.url).pathname.split("/").filter(Boolean);

  try {
    if (req.method === "GET") {
      const { data, error } = await db.from("app_users")
        .select("id,username,role,allowed_brands,active,created_at,last_login")
        .order("username");
      if (error) throw error;
      const { data: qrRows, error: qrError } = await db.from("app_user_qr_access")
        .select("user_id")
        .is("revoked_at", null);
      if (qrError) throw qrError;
      const activeQrUsers = new Set((qrRows || []).map((row) => row.user_id));
      return jsonResponse((data || []).map((user) => ({
        ...publicRecord(user),
        qr_active: activeQrUsers.has(user.id),
      })));
    }

    if ((req.method === "POST" || req.method === "DELETE") && path.length >= 3 && path[path.length - 1] === "qr") {
      const username = decodeURIComponent(path[path.length - 2]).toLowerCase();
      const { data: user, error } = await db.from("app_users")
        .select("id,username,role,active")
        .eq("username", username)
        .maybeSingle();
      if (error) throw error;
      if (!user) return jsonResponse({ detail: "ไม่พบบัญชีผู้ใช้นี้" }, 404);

      if (req.method === "DELETE") {
        const { error: revokeError } = await db.from("app_user_qr_access")
          .update({ revoked_at: new Date().toISOString() })
          .eq("user_id", user.id)
          .is("revoked_at", null);
        if (revokeError) throw revokeError;
        return jsonResponse({ detail: "ปิด QR สำหรับบัญชีนี้แล้ว" });
      }

      if (!user.active) return jsonResponse({ detail: "เปิดบัญชีผู้ใช้นี้ก่อนสร้าง QR" }, 400);
      if (user.role !== "user") return jsonResponse({ detail: "สร้าง QR ได้เฉพาะบัญชีผู้ใช้ทั่วไป" }, 400);

      const token = randomToken();
      const { error: saveError } = await db.from("app_user_qr_access").upsert({
        user_id: user.id,
        token_hash: await tokenHash(token),
        created_at: new Date().toISOString(),
        last_used_at: null,
        revoked_at: null,
      }, { onConflict: "user_id" });
      if (saveError) throw saveError;
      return jsonResponse({ username: user.username, qr_token: token });
    }

    if (req.method === "POST") {
      const body = await req.json();
      const username = String(body.username || "").trim().toLowerCase();
      const password = String(body.password || "");
      const role = String(body.role || "user").trim().toLowerCase();
      if (!usernamePattern.test(username)) {
        return jsonResponse({ detail: "ชื่อผู้ใช้ต้องยาว 3–32 ตัว และใช้ a-z, 0-9, _ หรือ - เท่านั้น" }, 400);
      }
      if (password.length < 8) return jsonResponse({ detail: "รหัสผ่านต้องยาวอย่างน้อย 8 ตัว" }, 400);
      if (role !== "admin" && role !== "user") return jsonResponse({ detail: "สิทธิ์ผู้ใช้ไม่ถูกต้อง" }, 400);
      const { data, error } = await db.from("app_users").insert({
        username,
        password_hash: await hashPassword(password),
        role,
        allowed_brands: cleanBrands(body.allowed_brands),
        active: Boolean(body.active),
      }).select("username,role,allowed_brands,active,created_at,last_login").single();
      if (error?.code === "23505") return jsonResponse({ detail: "มีชื่อผู้ใช้นี้แล้ว" }, 409);
      if (error) throw error;
      return jsonResponse(publicRecord(data), 201);
    }

    if (req.method === "PATCH" && path.length >= 2) {
      const username = decodeURIComponent(path[path.length - 1]).toLowerCase();
      const { data: existing, error: findError } = await db.from("app_users")
        .select("id,username,role,allowed_brands,active,created_at,last_login")
        .eq("username", username).maybeSingle();
      if (findError) throw findError;
      if (!existing) return jsonResponse({ detail: "ไม่พบบัญชีผู้ใช้นี้" }, 404);

      const body = await req.json();
      const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
      if (body.password !== undefined && body.password !== null && body.password !== "") {
        if (String(body.password).length < 8) return jsonResponse({ detail: "รหัสผ่านต้องยาวอย่างน้อย 8 ตัว" }, 400);
        patch.password_hash = await hashPassword(String(body.password));
      }
      if (body.role !== undefined) {
        const role = String(body.role).trim().toLowerCase();
        if (role !== "admin" && role !== "user") return jsonResponse({ detail: "สิทธิ์ผู้ใช้ไม่ถูกต้อง" }, 400);
        patch.role = role;
      }
      if (body.allowed_brands !== undefined) patch.allowed_brands = cleanBrands(body.allowed_brands);
      if (body.active !== undefined) patch.active = Boolean(body.active);

      if (username === admin.username && (patch.role === "user" || patch.active === false)) {
        return jsonResponse({ detail: "ห้ามปิดหรือลดสิทธิ์บัญชีที่กำลังใช้งานอยู่" }, 400);
      }
      const removesAdmin = existing.role === "admin" && (patch.role === "user" || patch.active === false);
      if (removesAdmin) {
        const { count, error } = await db.from("app_users").select("id", { count: "exact", head: true })
          .eq("role", "admin").eq("active", true);
        if (error) throw error;
        if ((count || 0) <= 1) return jsonResponse({ detail: "ต้องเหลือผู้ดูแลระบบที่เปิดใช้งานอย่างน้อย 1 คน" }, 400);
      }

      const { data, error } = await db.from("app_users").update(patch)
        .eq("id", existing.id)
        .select("username,role,allowed_brands,active,created_at,last_login").single();
      if (error) throw error;
      return jsonResponse(publicRecord(data));
    }

    return jsonResponse({ detail: "ไม่พบคำขอนี้" }, 404);
  } catch (error) {
    console.error("User management error:", error);
    return jsonResponse({ detail: "จัดการบัญชีไม่สำเร็จ กรุณาลองใหม่" }, 500);
  }
});

