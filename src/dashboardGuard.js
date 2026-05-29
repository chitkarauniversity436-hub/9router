import { NextRequest, NextResponse } from "next/server";
import { jwtVerify } from "jose";

import { getSettings } from "@/lib/localDb";
import { getConsistentMachineId } from "@/shared/utils/machineId";

/* -------------------------------------------------------------------------- */
/*                                   CONFIG                                   */
/* -------------------------------------------------------------------------- */

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.warn("⚠️ JWT_SECRET is not defined. Using insecure fallback secret.");
}

const SECRET = new TextEncoder().encode(
  JWT_SECRET || "9router-default-secret-change-me"
);

const CLI_TOKEN_HEADER = "x-9r-cli-token";
const CLI_TOKEN_SALT = "9r-cli-auth";

const ALWAYS_PROTECTED = [
  "/api/shutdown",
  "/api/settings/database",
];

const PROTECTED_API_PATHS = [
  "/api/settings",
  "/api/keys",
  "/api/providers/client",
  "/api/provider-nodes/validate",
];

const PUBLIC_PATHS = [
  "/login",
  "/favicon.ico",
];

/* -------------------------------------------------------------------------- */
/*                               CLI TOKEN CACHE                              */
/* -------------------------------------------------------------------------- */

let cachedCliToken: string | null = null;

async function getCliToken(): Promise<string> {
  if (!cachedCliToken) {
    cachedCliToken = await getConsistentMachineId(CLI_TOKEN_SALT);
  }

  return cachedCliToken;
}

/* -------------------------------------------------------------------------- */
/*                              AUTH VALIDATION                               */
/* -------------------------------------------------------------------------- */

async function verifyJwtToken(token?: string | null): Promise<boolean> {
  if (!token) return false;

  try {
    await jwtVerify(token, SECRET);
    return true;
  } catch {
    return false;
  }
}

async function hasValidJwt(request: NextRequest): Promise<boolean> {
  const token = request.cookies.get("auth_token")?.value;
  return verifyJwtToken(token);
}

async function hasValidCliToken(
  request: NextRequest
): Promise<boolean> {
  const token = request.headers.get(CLI_TOKEN_HEADER);

  if (!token) return false;

  const validToken = await getCliToken();

  return token === validToken;
}

/* -------------------------------------------------------------------------- */
/*                                SETTINGS LOAD                               */
/* -------------------------------------------------------------------------- */

type AppSettings = {
  requireLogin?: boolean;
  tunnelDashboardAccess?: boolean;
  tunnelUrl?: string;
  tailscaleUrl?: string;
};

async function loadSettings(): Promise<AppSettings | null> {
  try {
    return await getSettings();
  } catch (error) {
    console.error("Failed to load settings:", error);
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/*                             AUTHORIZATION LOGIC                            */
/* -------------------------------------------------------------------------- */

async function isAuthenticated(
  request: NextRequest
): Promise<boolean> {
  // JWT auth
  if (await hasValidJwt(request)) {
    return true;
  }

  // CLI auth
  if (await hasValidCliToken(request)) {
    return true;
  }

  // Login disabled
  const settings = await loadSettings();

  if (settings?.requireLogin === false) {
    return true;
  }

  return false;
}

/* -------------------------------------------------------------------------- */
/*                            TUNNEL ACCESS CHECK                             */
/* -------------------------------------------------------------------------- */

function extractHostname(value?: string): string {
  if (!value) return "";

  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return "";
  }
}

async function isTunnelAccessBlocked(
  request: NextRequest
): Promise<boolean> {
  const settings = await loadSettings();

  if (!settings) return false;

  if (settings.tunnelDashboardAccess === true) {
    return false;
  }

  const currentHost = (
    request.headers.get("host") || ""
  )
    .split(":")[0]
    .toLowerCase();

  const tunnelHost = extractHostname(settings.tunnelUrl);
  const tailscaleHost = extractHostname(settings.tailscaleUrl);

  return (
    (tunnelHost && currentHost === tunnelHost) ||
    (tailscaleHost && currentHost === tailscaleHost)
  );
}

/* -------------------------------------------------------------------------- */
/*                                MAIN PROXY                                  */
/* -------------------------------------------------------------------------- */

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  /* -------------------------------- PUBLIC -------------------------------- */

  if (
    PUBLIC_PATHS.some(
      (path) => pathname === path || pathname.startsWith(path)
    )
  ) {
    return NextResponse.next();
  }

  /* -------------------------- ALWAYS PROTECTED API ------------------------- */

  if (
    ALWAYS_PROTECTED.some((path) =>
      pathname.startsWith(path)
    )
  ) {
    const authorized =
      (await hasValidJwt(request)) ||
      (await hasValidCliToken(request));

    if (!authorized) {
      return NextResponse.json(
        {
          error: "Unauthorized",
          message: "Authentication required",
        },
        { status: 401 }
      );
    }

    return NextResponse.next();
  }

  /* --------------------------- PROTECTED API PATHS ------------------------- */

  if (
    PROTECTED_API_PATHS.some((path) =>
      pathname.startsWith(path)
    )
  ) {
    // Public endpoint
    if (pathname === "/api/settings/require-login") {
      return NextResponse.next();
    }

    const authenticated = await isAuthenticated(request);

    if (!authenticated) {
      return NextResponse.json(
        {
          error: "Unauthorized",
          message: "Authentication required",
        },
        { status: 401 }
      );
    }

    return NextResponse.next();
  }

  /* ----------------------------- DASHBOARD AUTH ---------------------------- */

  if (pathname.startsWith("/dashboard")) {
    // Tunnel restrictions
    if (await isTunnelAccessBlocked(request)) {
      return NextResponse.redirect(
        new URL("/login", request.url)
      );
    }

    const settings = await loadSettings();

    // Login disabled
    if (settings?.requireLogin === false) {
      return NextResponse.next();
    }

    // JWT required
    const validJwt = await hasValidJwt(request);

    if (!validJwt) {
      const loginUrl = new URL("/login", request.url);

      // preserve intended path
      loginUrl.searchParams.set("redirect", pathname);

      return NextResponse.redirect(loginUrl);
    }

    return NextResponse.next();
  }

  /* ----------------------------- ROOT REDIRECT ----------------------------- */

  if (pathname === "/") {
    return NextResponse.redirect(
      new URL("/dashboard", request.url)
    );
  }

  return NextResponse.next();
}

/* -------------------------------------------------------------------------- */
/*                                   MATCHER                                  */
/* -------------------------------------------------------------------------- */

export const config = {
  matcher: [
    "/",
    "/dashboard/:path*",
    "/api/:path*",
  ],
};
