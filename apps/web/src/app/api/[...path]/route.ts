import { NextRequest } from "next/server";

const nestApiUrl = process.env.NEST_API_URL ?? 'http://localhost:5006';

type RouteContext = {
    params: Promise<{
        path: string[];
    }>;
};

async function proxyToNest(request: NextRequest, context: RouteContext) {
    const { path: pathSegments } = await context.params;
    const path = pathSegments.join('/');

    const targetUrl = new URL(`${nestApiUrl}/api/${path}`);
    targetUrl.search = request.nextUrl.search;

    const headers = new Headers(request.headers);
    headers.delete('host');

    const hasBody = !['GET', 'HEAD'].includes(request.method);

    const response = await fetch(targetUrl, {
        method: request.method,
        headers,
        body: hasBody ? await request.text() : undefined,
        cache: 'no-store'
    });

    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
    });
}

export const GET = proxyToNest;
export const POST = proxyToNest;
export const PUT = proxyToNest;
export const PATCH = proxyToNest;
export const DELETE = proxyToNest;