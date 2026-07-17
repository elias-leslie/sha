import type { NextRequest } from "next/server";

const apiUrl = process.env.API_URL || "http://127.0.0.1:8010";

async function proxyRequest(request: NextRequest, path: string[]) {
  const target = new URL(`/api/${path.map(encodeURIComponent).join("/")}`, apiUrl);
  target.search = request.nextUrl.search;

  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("x-sha-external-auth");
  headers.delete("x-sha-external-role");
  headers.delete("x-sha-external-user");

  const response = await fetch(target, {
    method: request.method,
    headers,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer(),
    cache: "no-store",
    redirect: "manual",
  });
  const responseHeaders = new Headers(response.headers);
  const getSetCookie = (
    response.headers as Headers & { getSetCookie?: () => string[] }
  ).getSetCookie;
  if (getSetCookie) {
    const setCookies = getSetCookie.call(response.headers);
    responseHeaders.delete("set-cookie");
    for (const cookie of setCookies) {
      responseHeaders.append("set-cookie", cookie);
    }
  }
  responseHeaders.delete("content-encoding");
  responseHeaders.delete("content-length");
  return new Response(await response.arrayBuffer(), {
    status: response.status,
    headers: responseHeaders,
  });
}

type RouteContext = { params: Promise<{ path: string[] }> };

async function handle(request: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  return proxyRequest(request, path);
}

export { handle as DELETE, handle as GET, handle as PATCH, handle as POST, handle as PUT };
