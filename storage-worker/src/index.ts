import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";

interface Env {
  AUDIO: R2Bucket;
  SHEET_MUSIC: R2Bucket;
  SUPABASE_URL: string;
  SIGNING_SECRET: string;
}

const maximumValiditySeconds = 12 * 60 * 60;
const maximumPathsPerRequest = 100;
const signaturePattern = /^[0-9a-f]{64}$/;
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

async function loginRejection(request: Request, env: Env): Promise<string | null> {
  const header = request.headers.get("Authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (match === null) return "missing_token";
  try {
    await verifyToken(match[1], env);
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

async function signPaths(request: Request, env: Env): Promise<Response> {
  const rejection = await loginRejection(request, env);
  if (rejection !== null) return loginError();
  let body: unknown;
  try {
    body = await request.json();
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
    !paths.every((path) => typeof path === "string" && pathAllowed(path))
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
    if (url.pathname === "/sign") {
      if (request.method !== "POST") return errorResponse(405, "Nur POST");
      return signPaths(request, env);
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return errorResponse(405, "Nur GET und HEAD");
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
    return serveFile(request, env, bucketName, path);
  },
} satisfies ExportedHandler<Env>;
