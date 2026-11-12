import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2";

export type AppUser = {
  id: string;
  username: string;
  role: "admin" | "user";
  allowed_brands: string[];
  active: boolean;
  created_at?: string;
  last_login?: string | null;
  password_hash?: string;
};

export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
};

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

export function serviceClient(): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) throw new Error("Supabase server settings are missing");
  return createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function hmacKey(): Promise<CryptoKey> {
  const secret = Deno.env.get("APP_AUTH_SECRET");
  if (!secret || secret.length < 32) throw new Error("APP_AUTH_SECRET is not configured");
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function createAccessToken(username: string): Promise<string> {
  const expiresInHours = Number(Deno.env.get("TOKEN_EXPIRE_HOURS") || "12");
  const payload = {
    sub: username,
    exp: Math.floor(Date.now() / 1000) + expiresInHours * 3600,
  };
  const payloadPart = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign("HMAC", await hmacKey(), new TextEncoder().encode(payloadPart));
  return `${payloadPart}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

async function tokenUsername(token: string): Promise<string | null> {
  try {
    const [payloadPart, signaturePart] = token.split(".");
    if (!payloadPart || !signaturePart) return null;
    const payloadBytes = base64UrlToBytes(payloadPart);
    const signature = base64UrlToBytes(signaturePart);
    const valid = await crypto.subtle.verify(
      "HMAC",
      await hmacKey(),
      signature,
      new TextEncoder().encode(payloadPart),
    );
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
    if (!payload.sub || Number(payload.exp) < Math.floor(Date.now() / 1000)) return null;
    return String(payload.sub);
  } catch {
    return null;
  }
}

export async function getCurrentUser(req: Request): Promise<AppUser | null> {
  const header = req.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  const queryToken = new URL(req.url).searchParams.get("token");
  const token = match?.[1] || queryToken;
  if (!token) return null;
  const username = await tokenUsername(token);
  if (!username) return null;

  const { data, error } = await serviceClient()
    .from("app_users")
    .select("id,username,role,allowed_brands,active,created_at,last_login")
    .eq("username", username)
    .maybeSingle();
  if (error || !data || !data.active) return null;
  return data as AppUser;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  try {
    const [scheme, roundsText, saltText, digestText] = stored.split("$");
    const rounds = Number(roundsText);
    if (scheme !== "pbkdf2_sha256" || !Number.isInteger(rounds) || rounds < 100_000 || rounds > 2_000_000) {
      return false;
    }
    const salt = Uint8Array.from(saltText.match(/.{2}/g) || [], (x) => parseInt(x, 16));
    const expected = Uint8Array.from(digestText.match(/.{2}/g) || [], (x) => parseInt(x, 16));
    if (!salt.length || !expected.length) return false;
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const derived = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: rounds },
      material,
      expected.length * 8,
    ));
    if (derived.length !== expected.length) return false;
    let difference = 0;
    for (let i = 0; i < derived.length; i++) difference |= derived[i] ^ expected[i];
    return difference === 0;
  } catch {
    return false;
  }
}

export async function hashPassword(password: string): Promise<string> {
  const rounds = 310_000;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const digest = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: rounds },
    material,
    256,
  ));
  const hex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `pbkdf2_sha256$${rounds}$${hex(salt)}$${hex(digest)}`;
}

export async function requireAdmin(req: Request): Promise<AppUser | Response> {
  const user = await getCurrentUser(req);
  if (!user) return jsonResponse({ detail: "กรุณาเข้าสู่ระบบใหม่" }, 401);
  if (user.role !== "admin") return jsonResponse({ detail: "เฉพาะผู้ดูแลระบบเท่านั้น" }, 403);
  return user;
}

