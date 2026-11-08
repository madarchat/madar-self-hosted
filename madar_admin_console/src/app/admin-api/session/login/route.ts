import { NextRequest, NextResponse } from 'next/server';
import {
  attachSessionCookie,
  createSealedSession,
  forwardUpstream,
} from '@/lib/bff-session';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const loginPayload = {
      device_name: 'Madar Admin Console Web',
      platform: 'web',
      device_pub_key: 'admin-console-bff-session',
      attestation_token: 'admin-console-bff-verified',
      ...body,
    };

    const upstream = await forwardUpstream(
      'POST',
      '/api/v1/auth/workspace/login',
      loginPayload,
      null,
    );

    if (upstream.status >= 200 && upstream.status < 300 && upstream.data?.access_token) {
      const { sealedCookie, session } = createSealedSession(
        upstream.data.access_token,
        upstream.data.user || null,
      );
      const safeResponse = { ...upstream.data };
      delete safeResponse.access_token;
      delete safeResponse.refresh_token;

      const res = NextResponse.json({
        authenticated: true,
        csrf_token: session.csrfToken,
        ...safeResponse,
      });
      attachSessionCookie(res, sealedCookie);
      return res;
    }

    return NextResponse.json(upstream.data, { status: upstream.status });
  } catch (err: any) {
    return NextResponse.json(
      {
        error: {
          code: 'bff_login_error',
          message: err?.message || 'Login gateway error',
        },
      },
      { status: 502 },
    );
  }
}
