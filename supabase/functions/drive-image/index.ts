import { corsHeaders, getCurrentUser, jsonResponse, serviceClient } from "../_shared/auth.ts";
import { findDriveFileByPath, getGoogleAccessToken } from "../_shared/drive.ts";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "GET" && req.method !== "HEAD") return jsonResponse({ detail: "ไม่รองรับคำขอนี้" }, 405);

  const user = await getCurrentUser(req);
  if (!user) return jsonResponse({ detail: "กรุณาเข้าสู่ระบบใหม่" }, 401);

  const url = new URL(req.url);
  const path = String(url.searchParams.get("path") || "").trim();
  const variant = url.searchParams.get("variant") === "thumb" ? "thumb" : "original";
  if (!path) return jsonResponse({ detail: "ไม่พบตำแหน่งรูป" }, 400);

  try {
    const { data: image, error } = await serviceClient().from("images")
      .select("id,drive_path,drive_file_id,thumbnail_drive_file_id,file_name,category,case_id")
      .eq("drive_path", path)
      .maybeSingle();
    if (error) throw error;
    if (!image) return jsonResponse({ detail: "ไม่พบรูปในคลัง Drive" }, 404);

    const { data: caseRow, error: caseError } = await serviceClient().from("cases")
      .select("brand").eq("case_id", image.case_id).maybeSingle();
    if (caseError) throw caseError;
    if (!caseRow) return jsonResponse({ detail: "ไม่พบเคสของรูปนี้" }, 404);
    if (user.role !== "admin" && !(user.allowed_brands || []).some((brand) =>
      brand.toUpperCase() === "ALL" || brand.toLowerCase() === String(caseRow.brand || "").toLowerCase()
    )) return jsonResponse({ detail: "ไม่มีสิทธิ์เปิดรูปนี้" }, 403);

    let fileId = variant === "thumb" && image.thumbnail_drive_file_id
      ? image.thumbnail_drive_file_id
      : image.drive_file_id;
    let googleToken = "";
    if (!fileId && image.drive_path) {
      googleToken = await getGoogleAccessToken();
      fileId = await findDriveFileByPath(googleToken, image.drive_path);
      if (fileId) {
        const { error: updateError } = await serviceClient().from("images")
          .update({ drive_file_id: fileId }).eq("id", image.id).is("drive_file_id", null);
        if (updateError) throw updateError;
      }
    }
    if (!fileId) return jsonResponse({ detail: "ยังหารูปนี้ใน Google Drive ไม่พบ" }, 404);

    if (!googleToken) googleToken = await getGoogleAccessToken();
    const range = req.headers.get("Range");
    const driveResponse = await fetch(
      `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media&supportsAllDrives=true`,
      { headers: { Authorization: `Bearer ${googleToken}`, ...(range ? { Range: range } : {}) } },
    );
    if (!driveResponse.ok || !driveResponse.body) {
      return jsonResponse({ detail: `Google Drive เปิดรูปไม่ได้ (${driveResponse.status})` }, driveResponse.status === 404 ? 404 : 502);
    }

    const headers = new Headers({
      ...corsHeaders,
      "Content-Type": driveResponse.headers.get("Content-Type") || "image/jpeg",
      "Cache-Control": "private, max-age=300",
      "X-Content-Type-Options": "nosniff",
      "Content-Disposition": "inline",
    });
    for (const name of ["Content-Length", "Content-Range", "Accept-Ranges"]) {
      const value = driveResponse.headers.get(name);
      if (value) headers.set(name, value);
    }
    return new Response(req.method === "HEAD" ? null : driveResponse.body, {
      status: driveResponse.status,
      headers,
    });
  } catch (error) {
    console.error("Drive image error:", error);
    return jsonResponse({ detail: "เปิดรูปจาก Google Drive ไม่สำเร็จ" }, 502);
  }
});

