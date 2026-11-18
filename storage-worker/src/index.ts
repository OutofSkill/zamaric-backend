import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";

interface Env {
  AUDIO: R2Bucket;
  SHEET_MUSIC: R2Bucket;
  SUPABASE_URL: string;
  SUPABASE_PUBLISHABLE_KEY: string;
  SIGNING_SECRET: string;
}

const maximumValiditySeconds = 12 * 60 * 60;
const maximumPathsPerRequest = 100;
const maximumSignBodyBytes = 64 * 1024;
const maximumPathLength = 512;
const listPageSize = 1000;
const signaturePattern = /^[0-9a-f]{64}$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const sha256Header = "X-Content-SHA256";
const storageHealthKey = "health-check";
const uploadTypes: Record<string, { pattern: RegExp; contentType: string }> = {
  audio: {
    pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.mp3$/,
    contentType: "audio/mpeg",
  },
  sheet_music: {
    pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.pdf$/,
    contentType: "application/pdf",
  },
};
const keySetLifetimeMilliseconds = 10 * 60 * 1000;
const userAgent = "zamaric-storage-worker/1.0";

let keySet: ReturnType<typeof createLocalJWKSet> | undefined;
let keySetUrl: string | undefined;
let keySetLoadedAt = 0;
let signingKey: CryptoKey | undefined;
let signingKeySecret: string | undefined;

function bucketFor(env: Env, name: string): R2Bucket | undefined {
  switch (name) {
    case "audio":
      return env.AUDIO;
    case "sheet_music":
      return env.SHEET_MUSIC;
    default:
      return undefined;
  }
}

function supabaseBase(env: Env): string {
  return env.SUPABASE_URL.trim().replace(/\/+$/, "");
}

class KeySetUnavailable extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

async function publicKeySet(
  env: Env,
  reload = false,
): Promise<ReturnType<typeof createLocalJWKSet>> {
  const url = `${supabaseBase(env)}/auth/v1/.well-known/jwks.json`;
  const fresh =
    keySet !== undefined &&
    keySetUrl === url &&
    Date.now() - keySetLoadedAt < keySetLifetimeMilliseconds;
  if (fresh && !reload) return keySet!;
  let response: Response;
  try {
    response = await fetch(url, {
      headers: { "User-Agent": userAgent, Accept: "application/json" },
    });
  } catch {
    throw new KeySetUnavailable("jwks_unreachable");
  }
  if (response.status !== 200) {
    throw new KeySetUnavailable(`jwks_status_${response.status}`);
  }
  keySet = createLocalJWKSet((await response.json()) as JSONWebKeySet);
  keySetUrl = url;
  keySetLoadedAt = Date.now();
  return keySet;
}

async function verifyToken(token: string, env: Env): Promise<void> {
  const options = {
    issuer: `${supabaseBase(env)}/auth/v1`,
    audience: "authenticated",
  };
  try {
    await jwtVerify(token, await publicKeySet(env), options);
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ERR_JWKS_NO_MATCHING_KEY"
    ) {
      await jwtVerify(token, await publicKeySet(env, true), options);
      return;
    }
    throw error;
  }
}

async function hmacKey(env: Env): Promise<CryptoKey> {
  if (signingKey === undefined || signingKeySecret !== env.SIGNING_SECRET) {
    signingKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.SIGNING_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
    signingKeySecret = env.SIGNING_SECRET;
  }
  return signingKey;
}

function signedContent(bucket: string, path: string, expires: number): Uint8Array {
  return new TextEncoder().encode(`${bucket}/${path}\n${expires}`);
}

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function signature(
  env: Env,
  bucket: string,
  path: string,
  expires: number,
): Promise<string> {
  const key = await hmacKey(env);
  return toHex(
    await crypto.subtle.sign("HMAC", key, signedContent(bucket, path, expires)),
  );
}

async function signatureValid(
  env: Env,
  bucket: string,
  path: string,
  expiresText: string,
  signatureText: string,
): Promise<boolean> {
  const expires = Number(expiresText);
  if (!Number.isInteger(expires) || expires < Date.now() / 1000) return false;
  if (!signaturePattern.test(signatureText)) return false;
  const key = await hmacKey(env);
  return crypto.subtle.verify(
    "HMAC",
    key,
    fromHex(signatureText),
    signedContent(bucket, path, expires),
  );
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get("Authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match === null ? null : match[1];
}

async function loginRejection(request: Request, env: Env): Promise<string | null> {
  const token = bearerToken(request);
  if (token === null) return "missing_token";
  try {
    await verifyToken(token, env);
    return null;
  } catch (error) {
    const code =
      typeof error === "object" && error !== null && "code" in error
        ? String(error.code)
        : error instanceof Error
          ? error.name
          : "unknown";
    const claim =
      typeof error === "object" && error !== null && "claim" in error
        ? `:${String(error.claim)}`
        : "";
    return `${code}${claim}`;
  }
}

function loginError(): Response {
  return errorResponse(401, "Nicht angemeldet");
}

class DatabaseUnavailable extends Error {}

async function databaseCall(
  env: Env,
  token: string,
  functionName: string,
  parameters: Record<string, unknown>,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(`${supabaseBase(env)}/rest/v1/rpc/${functionName}`, {
      method: "POST",
      headers: {
        apikey: env.SUPABASE_PUBLISHABLE_KEY,
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": userAgent,
      },
      body: JSON.stringify(parameters),
    });
  } catch {
    throw new DatabaseUnavailable();
  }
  if (response.status !== 200) throw new DatabaseUnavailable();
  return response.json();
}

function databaseError(): Response {
  return errorResponse(502, "Datenbank nicht erreichbar");
}

function storageError(): Response {
  return errorResponse(502, "Speicher nicht erreichbar");
}

async function adminToken(request: Request, env: Env): Promise<string | Response> {
  const token = bearerToken(request);
  if (token === null) return loginError();
  try {
    await verifyToken(token, env);
  } catch (error) {
    if (error instanceof KeySetUnavailable) {
      return errorResponse(502, "Supabase nicht erreichbar");
    }
    return loginError();
  }
  try {
    if ((await databaseCall(env, token, "is_admin", {})) !== true) {
      return errorResponse(403, "Keine Berechtigung");
    }
  } catch {
    return databaseError();
  }
  return token;
}

function pathAllowed(path: string): boolean {
  return (
    path.length > 0 &&
    !path.startsWith("/") &&
    !path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  );
}

function errorResponse(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function contentRange(range: R2Range, size: number): { start: number; end: number } {
  if ("suffix" in range) {
    const start = Math.max(0, size - range.suffix);
    return { start, end: size - 1 };
  }
  const start = range.offset ?? 0;
  const length = range.length ?? size - start;
  return { start, end: Math.min(size, start + length) - 1 };
}

function objectHeaders(object: R2Object): Headers {
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Cache-Control", "private, max-age=3600");
  return headers;
}

async function serveFile(
  request: Request,
  env: Env,
  bucketName: string,
  path: string,
): Promise<Response> {
  const bucket = bucketFor(env, bucketName);
  if (bucket === undefined || !pathAllowed(path)) {
    return errorResponse(404, "Nicht gefunden");
  }
  const url = new URL(request.url);
  const expires = url.searchParams.get("expires");
  const signatureText = url.searchParams.get("signature");
  if (expires !== null && signatureText !== null) {
    if (!(await signatureValid(env, bucketName, path, expires, signatureText))) {
      return errorResponse(401, "Nicht angemeldet");
    }
  } else {
    const rejection = await loginRejection(request, env);
    if (rejection !== null) return loginError();
  }

  if (request.method === "HEAD") {
    const head = await bucket.head(path);
    if (head === null) return errorResponse(404, "Nicht gefunden");
    const headers = objectHeaders(head);
    headers.set("Content-Length", String(head.size));
    return new Response(null, { headers });
  }

  let object: R2ObjectBody | R2Object | null;
  try {
    object = await bucket.get(path, {
      range: request.headers,
      onlyIf: request.headers,
    });
  } catch {
    const head = await bucket.head(path);
    if (head === null) return errorResponse(404, "Nicht gefunden");
    return new Response(null, {
      status: 416,
      headers: { "Content-Range": `bytes */${head.size}` },
    });
  }
  if (object === null) return errorResponse(404, "Nicht gefunden");
  const headers = objectHeaders(object);
  if (!("body" in object)) {
    return new Response(null, { status: 304, headers });
  }
  const range = object.range;
  if (range !== undefined && request.headers.has("Range")) {
    const { start, end } = contentRange(range, object.size);
    headers.set("Content-Range", `bytes ${start}-${end}/${object.size}`);
    headers.set("Content-Length", String(end - start + 1));
    return new Response(object.body, { status: 206, headers });
  }
  headers.set("Content-Length", String(object.size));
  return new Response(object.body, { headers });
}

async function limitedBody(request: Request, limit: number): Promise<string | null> {
  if (Number(request.headers.get("Content-Length") ?? 0) > limit) return null;
  if (request.body === null) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

async function signPaths(request: Request, env: Env): Promise<Response> {
  const rejection = await loginRejection(request, env);
  if (rejection !== null) return loginError();
  let text: string | null;
  try {
    text = await limitedBody(request, maximumSignBodyBytes);
  } catch {
    return errorResponse(400, "Anfrage abgebrochen");
  }
  if (text === null) return errorResponse(413, "Anfrage zu groß");
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return errorResponse(400, "Ungültiges JSON");
  }
  const { bucket, paths, expiresIn } = (body ?? {}) as {
    bucket?: unknown;
    paths?: unknown;
    expiresIn?: unknown;
  };
  if (typeof bucket !== "string" || bucketFor(env, bucket) === undefined) {
    return errorResponse(400, "Unbekannter Bucket");
  }
  if (
    !Array.isArray(paths) ||
    paths.length === 0 ||
    paths.length > maximumPathsPerRequest ||
    !paths.every(
      (path) =>
        typeof path === "string" && path.length <= maximumPathLength && pathAllowed(path),
    )
  ) {
    return errorResponse(400, "Ungültige Pfade");
  }
  const validity =
    typeof expiresIn === "number" && Number.isFinite(expiresIn) && expiresIn > 0
      ? Math.min(Math.floor(expiresIn), maximumValiditySeconds)
      : maximumValiditySeconds;
  const expires = Math.floor(Date.now() / 1000) + validity;
  const origin = new URL(request.url).origin;
  const urls = await Promise.all(
    (paths as string[]).map(async (path) => ({
      path,
      url:
        `${origin}/${bucket}/${encodeURIComponent(path)}` +
        `?expires=${expires}&signature=${await signature(env, bucket, path, expires)}`,
      expiresAt: expires,
    })),
  );
  return new Response(JSON.stringify({ urls }), {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

async function storeFile(
  request: Request,
  env: Env,
  bucketName: string,
  path: string,
): Promise<Response> {
  const bucket = bucketFor(env, bucketName);
  if (bucket === undefined || !uploadTypes[bucketName].pattern.test(path)) {
    return errorResponse(400, "Ungültiger Dateiname");
  }
  const token = await adminToken(request, env);
  if (token instanceof Response) return token;
  const length = Number(request.headers.get("Content-Length"));
  if (!Number.isInteger(length) || length <= 0 || request.body === null) {
    return errorResponse(411, "Dateigröße fehlt");
  }
  const sha256 = request.headers.get(sha256Header) ?? "";
  if (!sha256Pattern.test(sha256)) {
    return errorResponse(400, "Prüfsumme fehlt");
  }
  const referencedBefore = await fileReferenced(env, token, bucketName, path);
  if (referencedBefore instanceof Response) return referencedBefore;
  if (referencedBefore) return errorResponse(409, "Datei gehört schon zu einem Song");
  let object: R2Object | null;
  try {
    if ((await bucket.head(path)) !== null) {
      return errorResponse(409, "Datei existiert schon");
    }
    object = await bucket.put(path, request.body, {
      onlyIf: { etagDoesNotMatch: "*" },
      httpMetadata: { contentType: uploadTypes[bucketName].contentType },
      sha256,
    });
  } catch {
    return storageError();
  }
  if (object === null) return errorResponse(409, "Datei existiert schon");
  const referencedAfter = await fileReferenced(env, token, bucketName, path);
  if (referencedAfter !== false) {
    try {
      await bucket.delete(path);
    } catch {
      return storageError();
    }
    if (referencedAfter instanceof Response) return referencedAfter;
    return errorResponse(409, "Datei gehört schon zu einem Song");
  }
  return jsonResponse({ name: object.key, bytes: object.size }, 201);
}

async function fileReferenced(
  env: Env,
  token: string,
  bucketName: string,
  path: string,
): Promise<boolean | Response> {
  let referenced: unknown;
  try {
    referenced = await databaseCall(env, token, "file_is_referenced", {
      bucket_name: bucketName,
      file_name: path,
    });
  } catch {
    return databaseError();
  }
  if (typeof referenced !== "boolean") return databaseError();
  return referenced;
}

async function deleteUnusedFiles(request: Request, env: Env): Promise<Response> {
  const token = await adminToken(request, env);
  if (token instanceof Response) return token;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, "Ungültiges JSON");
  }
  const { bucket: bucketName, names } = (body ?? {}) as {
    bucket?: unknown;
    names?: unknown;
  };
  if (typeof bucketName !== "string") return errorResponse(400, "Unbekannter Bucket");
  const bucket = bucketFor(env, bucketName);
  if (bucket === undefined) return errorResponse(400, "Unbekannter Bucket");
  if (
    !Array.isArray(names) ||
    names.length === 0 ||
    names.length > maximumPathsPerRequest ||
    !names.every((name) => typeof name === "string" && pathAllowed(name))
  ) {
    return errorResponse(400, "Ungültige Namen");
  }
  let heads: (R2Object | null)[];
  try {
    heads = await Promise.all(
      [...new Set(names as string[])].map((name) => bucket.head(name)),
    );
  } catch {
    return storageError();
  }
  const files = heads
    .filter((head): head is R2Object => head !== null)
    .map((head) => ({
      bucket: bucketName,
      name: head.key,
      uploaded_at: head.uploaded.toISOString(),
    }));
  if (files.length === 0) return jsonResponse({ deleted: [] });
  let rows: unknown;
  try {
    rows = await databaseCall(env, token, "unused_files", { files });
  } catch {
    return databaseError();
  }
  if (!Array.isArray(rows)) return databaseError();
  const requested = new Set(files.map((file) => file.name));
  const deletable = (rows as { bucket?: unknown; name?: unknown }[])
    .filter((row) => row.bucket === bucketName && typeof row.name === "string")
    .map((row) => row.name as string)
    .filter((name) => requested.has(name));
  if (deletable.length > 0) {
    try {
      await bucket.delete(deletable);
    } catch {
      return storageError();
    }
  }
  return jsonResponse({ deleted: deletable });
}

async function listFiles(request: Request, env: Env, bucketName: string): Promise<Response> {
  const bucket = bucketFor(env, bucketName);
  if (bucket === undefined) return errorResponse(404, "Nicht gefunden");
  const token = await adminToken(request, env);
  if (token instanceof Response) return token;
  const files: { bucket: string; name: string; bytes: number; uploaded_at: string }[] = [];
  let cursor: string | undefined;
  try {
    do {
      const page = await bucket.list({ limit: listPageSize, cursor });
      for (const object of page.objects) {
        files.push({
          bucket: bucketName,
          name: object.key,
          bytes: object.size,
          uploaded_at: object.uploaded.toISOString(),
        });
      }
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor !== undefined);
  } catch {
    return storageError();
  }
  return jsonResponse({ files });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return errorResponse(405, "Nur GET und HEAD");
      }
      return new Response(
        request.method === "HEAD" ? null : JSON.stringify({ ok: true }),
        {
          headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
        },
      );
    }
    if (url.pathname === "/health/storage") {
      if (request.method !== "GET") return errorResponse(405, "Nur GET");
      try {
        await env.AUDIO.head(storageHealthKey);
      } catch {
        return storageError();
      }
      return jsonResponse({ ok: true });
    }
    if (url.pathname === "/sign") {
      if (request.method !== "POST") return errorResponse(405, "Nur POST");
      return signPaths(request, env);
    }
    if (url.pathname === "/delete") {
      if (request.method !== "POST") return errorResponse(405, "Nur POST");
      return deleteUnusedFiles(request, env);
    }
    if (url.pathname.startsWith("/list/")) {
      if (request.method !== "GET") return errorResponse(405, "Nur GET");
      return listFiles(request, env, url.pathname.slice("/list/".length));
    }
    if (request.method !== "GET" && request.method !== "HEAD" && request.method !== "PUT") {
      return errorResponse(405, "Nur GET, HEAD und PUT");
    }
    const separator = url.pathname.indexOf("/", 1);
    if (separator < 0) return errorResponse(404, "Nicht gefunden");
    const bucketName = url.pathname.slice(1, separator);
    let path: string;
    try {
      path = decodeURIComponent(url.pathname.slice(separator + 1));
    } catch {
      return errorResponse(400, "Ungültiger Pfad");
    }
    if (request.method === "PUT") return storeFile(request, env, bucketName, path);
    return serveFile(request, env, bucketName, path);
  },
} satisfies ExportedHandler<Env>;
