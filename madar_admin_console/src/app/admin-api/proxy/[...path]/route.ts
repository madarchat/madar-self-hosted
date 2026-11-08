import { NextRequest, NextResponse } from 'next/server';
import {
  attachSessionCookie,
  createSealedSession,
  forwardUpstream,
  readSessionFromRequest,
  verifyCsrfToken,
} from '@/lib/bff-session';

export const dynamic = 'force-dynamic';

function normalizeUpstreamSubpath(rawSubpath: string): string {
  if (rawSubpath.startsWith('/api/v1/')) {
    return rawSubpath;
  }
  if (
    rawSubpath.startsWith('/admin/') ||
    rawSubpath.startsWith('/broadcasts') ||
    rawSubpath.startsWith('/channels') ||
    rawSubpath.startsWith('/decisions') ||
    rawSubpath.startsWith('/server/')
  ) {
    return `/api/v1${rawSubpath}`;
  }
  return `/api/v1/admin${rawSubpath}`;
}

async function handleProxy(
  req: NextRequest,
  { params }: { params: { path: string[] } },
) {
  try {
    const pathSegments = params.path || [];
    const rawSubpath = '/' + pathSegments.join('/');
    const normalizedSubpath = normalizeUpstreamSubpath(rawSubpath);
    const search = req.nextUrl.search || '';
    const upstreamPath = `${normalizedSubpath}${search}`;

    const session = readSessionFromRequest(req);
    const method = req.method || 'GET';
    const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

    if (session && isMutating) {
      const csrfHeader = req.headers.get('x-madar-csrf');
      if (!verifyCsrfToken(csrfHeader, session.csrfToken)) {
        return NextResponse.json(
          {
            error: {
              code: 'csrf_validation_failed',
              message: 'CSRF token validation failed (X-Madar-CSRF)',
            },
          },
          { status: 403 },
        );
      }
    }

    let body: unknown = undefined;
    if (isMutating) {
      const text = await req.text();
      if (text) {
        try {
          body = JSON.parse(text);
        } catch {
          body = {};
        }
      } else {
        body = {};
      }
    }

    const upstream = await forwardUpstream(
      method,
      upstreamPath,
      body,
      session?.jwt || null,
    );

    if (upstream.contentType.includes('text/csv')) {
      return new NextResponse(upstream.rawText || '', {
        status: upstream.status,
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': 'attachment; filename="madar-audit-log.csv"',
        },
      });
    }

    if (
      upstreamPath.startsWith('/api/v1/admin/setup') &&
      upstream.status >= 200 &&
      upstream.status < 300 &&
      upstream.data?.access_token
    ) {
      const { sealedCookie, session: newSession } = createSealedSession(
        upstream.data.access_token,
        upstream.data.admin_user || null,
      );
      const safeData = { ...upstream.data, csrf_token: newSession.csrfToken };
      delete safeData.access_token;
      const res = NextResponse.json(safeData, { status: upstream.status });
      attachSessionCookie(res, sealedCookie);
      return res;
    }

    return NextResponse.json(upstream.data, { status: upstream.status });
  } catch (err: any) {
    return NextResponse.json(
      {
        error: {
          code: 'bff_gateway_error',
          message: err?.message || 'Isolated Control-Plane BFF gateway error',
        },
      },
      { status: 502 },
    );
  }
}

export const GET = handleProxy;
export const POST = handleProxy;
export const PUT = handleProxy;
export const PATCH = handleProxy;
export const DELETE = handleProxy;
