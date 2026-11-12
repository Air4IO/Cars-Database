const DRIVE_API = "https://www.googleapis.com/drive/v3";
const DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3";
const FOLDER_MIME = "application/vnd.google-apps.folder";

export async function getGoogleAccessToken(): Promise<string> {
  const clientId = Deno.env.get("GOOGLE_OAUTH_CLIENT_ID");
  const clientSecret = Deno.env.get("GOOGLE_OAUTH_CLIENT_SECRET");
  const refreshToken = Deno.env.get("GOOGLE_OAUTH_REFRESH_TOKEN");
  if (!clientId || !clientSecret || !refreshToken) throw new Error("Google Drive access is not configured");

  const form = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken,
    grant_type: "refresh_token",
  });
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
  });
  if (!response.ok) throw new Error(`Google sign-in refresh failed (${response.status})`);
  const data = await response.json();
  if (!data.access_token) throw new Error("Google did not return an access key");
  return data.access_token;
}

async function findChildFolder(token: string, parentId: string, name: string): Promise<string | null> {
  const safeName = name.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  const q = `'${parentId}' in parents and name='${safeName}' and mimeType='${FOLDER_MIME}' and trashed=false`;
  const params = new URLSearchParams({ q, fields: "files(id,name)", pageSize: "10", supportsAllDrives: "true", includeItemsFromAllDrives: "true" });
  const response = await fetch(`${DRIVE_API}/files?${params}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) throw new Error(`Google Drive folder search failed (${response.status})`);
  const result = await response.json();
  return result.files?.[0]?.id || null;
}

async function createFolder(token: string, parentId: string, name: string): Promise<string> {
  const response = await fetch(`${DRIVE_API}/files?supportsAllDrives=true&fields=id,name`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name, mimeType: FOLDER_MIME, parents: [parentId] }),
  });
  if (!response.ok) throw new Error(`Google Drive folder creation failed (${response.status})`);
  const result = await response.json();
  return result.id;
}

export async function getOrCreateFolder(token: string, parentId: string, name: string): Promise<string> {
  return await findChildFolder(token, parentId, name) || await createFolder(token, parentId, name);
}

export async function getWebCaseFolder(token: string, year: string, caseId: string): Promise<{ id: string; path: string }> {
  const rootId = Deno.env.get("DRIVE_ROOT_FOLDER_ID") || "11r6rLHnNFUj15KsJ1A5ebDERyQWKWjMC";
  const webRoot = await getOrCreateFolder(token, rootId, "AIR4 Web Cases");
  const yearFolder = await getOrCreateFolder(token, webRoot, year);
  const caseFolder = await getOrCreateFolder(token, yearFolder, caseId);
  return { id: caseFolder, path: `AIR4 Web Cases/${year}/${caseId}` };
}

export async function getWebCasesRootId(token: string): Promise<string> {
  const rootId = Deno.env.get("DRIVE_ROOT_FOLDER_ID") || "11r6rLHnNFUj15KsJ1A5ebDERyQWKWjMC";
  return await findChildFolder(token, rootId, "AIR4 Web Cases") || "";
}

export async function findDriveFileByPath(token: string, drivePath: string): Promise<string | null> {
  const rootId = Deno.env.get("DRIVE_ROOT_FOLDER_ID") || "11r6rLHnNFUj15KsJ1A5ebDERyQWKWjMC";
  const parts = String(drivePath || "").replace(/\\/g, "/").split("/").map((part) => part.trim()).filter(Boolean);
  if (parts.length < 2) return null;

  let parentId = rootId;
  for (const folderName of parts.slice(0, -1)) {
    const safeName = folderName.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
    const params = new URLSearchParams({
      q: `'${parentId}' in parents and name='${safeName}' and mimeType='${FOLDER_MIME}' and trashed=false`,
      fields: "files(id,name)",
      pageSize: "10",
      supportsAllDrives: "true",
      includeItemsFromAllDrives: "true",
    });
    const response = await fetch(`${DRIVE_API}/files?${params}`, { headers: { Authorization: `Bearer ${token}` } });
    if (!response.ok) throw new Error(`Google Drive folder lookup failed (${response.status})`);
    const result = await response.json();
    if (!Array.isArray(result.files) || result.files.length !== 1 || !result.files[0]?.id) return null;
    parentId = result.files[0].id;
  }

  const fileName = parts[parts.length - 1];
  const safeFileName = fileName.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  const params = new URLSearchParams({
    q: `'${parentId}' in parents and name='${safeFileName}' and mimeType!='${FOLDER_MIME}' and trashed=false`,
    fields: "files(id,name,mimeType)",
    pageSize: "10",
    supportsAllDrives: "true",
    includeItemsFromAllDrives: "true",
  });
  const response = await fetch(`${DRIVE_API}/files?${params}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) throw new Error(`Google Drive file lookup failed (${response.status})`);
  const result = await response.json();
  if (!Array.isArray(result.files) || result.files.length !== 1 || !result.files[0]?.id) return null;
  return result.files[0].id;
}

export async function isFileInsideFolderTree(token: string, fileId: string, rootFolderId: string): Promise<boolean> {
  let pending = [fileId];
  const seen = new Set<string>();
  for (let depth = 0; depth < 12 && pending.length; depth++) {
    const next: string[] = [];
    for (const id of pending) {
      if (id === rootFolderId) return true;
      if (seen.has(id)) continue;
      seen.add(id);
      const params = new URLSearchParams({ fields: "id,parents", supportsAllDrives: "true" });
      const response = await fetch(`${DRIVE_API}/files/${encodeURIComponent(id)}?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) continue;
      const info = await response.json();
      next.push(...(Array.isArray(info.parents) ? info.parents : []));
    }
    pending = next;
  }
  return false;
}

export async function startDriveUpload(
  token: string,
  folderId: string,
  fileName: string,
  mimeType: string,
  size?: string | null,
): Promise<string> {
  const url = new URL(`${DRIVE_UPLOAD_API}/files`);
  url.searchParams.set("uploadType", "resumable");
  url.searchParams.set("supportsAllDrives", "true");
  url.searchParams.set("fields", "id,name,mimeType,parents");
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json; charset=UTF-8",
    "X-Upload-Content-Type": mimeType,
  };
  if (size && /^\d+$/.test(size)) headers["X-Upload-Content-Length"] = size;
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ name: fileName, parents: [folderId] }),
  });
  if (!response.ok) throw new Error(`Google Drive could not start the upload (${response.status})`);
  const location = response.headers.get("Location");
  if (!location) throw new Error("Google Drive did not return an upload link");
  return location;
}

export async function uploadStreamToDrive(
  uploadUrl: string,
  token: string,
  body: ReadableStream<Uint8Array>,
  mimeType: string,
): Promise<Record<string, unknown>> {
  const response = await fetch(uploadUrl, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": mimeType },
    body,
  });
  if (!response.ok) throw new Error(`Google Drive upload failed (${response.status})`);
  return await response.json();
}

export async function trashDriveFile(token: string, fileId: string): Promise<void> {
  const response = await fetch(`${DRIVE_API}/files/${encodeURIComponent(fileId)}?supportsAllDrives=true`, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ trashed: true }),
  });
  if (!response.ok && response.status !== 404) throw new Error(`Google Drive could not move a file to Trash (${response.status})`);
}

