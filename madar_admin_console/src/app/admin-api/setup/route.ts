import { NextRequest, NextResponse } from 'next/server';
import {
  attachSessionCookie,
  createSealedSession,
  forwardUpstream,
  readSessionFromRequest,
} from '@/lib/bff-session';

export const dynamic = 'force-dynamic';

/**
 * POST /admin-api/setup
 * Completes the First-Time Organization & Initial Super-Admin Registration Wizard (/setup),
 * then automatically logs the newly created SUPER_ADMIN into an HttpOnly BFF session so
 * they land directly in the ready-to-use Admin Console Dashboard with their initial QR code.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const existingSession = readSessionFromRequest(req);

    const setupRes = await forwardUpstream(
      'POST',
      '/api/v1/admin/setup',
      body,
      existingSession?.jwt || null,
    );

    if (setupRes.status < 200 || setupRes.status >= 300) {
      return NextResponse.json(setupRes.data, { status: setupRes.status });
    }

    // Automatically authenticate the newly created SUPER_ADMIN account via /api/v1/auth/workspace/login
    const adminInput = body?.admin_user;
    if (adminInput?.employee_no && adminInput?.password) {
      const loginRes = await forwardUpstream('POST', '/api/v1/auth/workspace/login', {
        identifier: adminInput.employee_no,
        password: adminInput.password,
        device_name: 'Madar Admin Console Web',
        platform: 'web',
        device_pub_key: 'admin-console-bff-session',
        attestation_token: 'admin-console-bff-verified',
      });

      if (loginRes.status >= 200 && loginRes.status < 300 && loginRes.data?.access_token) {
        const { sealedCookie, session } = createSealedSession(
          loginRes.data.access_token,
          loginRes.data.user || setupRes.data?.admin_user || null,
        );
        const res = NextResponse.json(
          {
            ...setupRes.data,
            authenticated: true,
            csrf_token: session.csrfToken,
            user: loginRes.data.user || setupRes.data?.admin_user,
          },
          { status: 201 },
        );
        attachSessionCookie(res, sealedCookie);
        return res;
      }
    }

    return NextResponse.json(setupRes.data, { status: setupRes.status });
  } catch (err: any) {
    return NextResponse.json(
      {
        error: {
          code: 'bff_setup_error',
          message: err?.message || 'Failed to complete first-time organization setup',
        },
      },
      { status: 502 },
    );
  }
}
