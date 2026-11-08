import { NextRequest, NextResponse } from 'next/server';
import { attachSessionCookie, createSealedSession } from '@/lib/bff-session';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const token = String(body?.token || '').trim();
    if (!token) {
      return NextResponse.json(
        { error: { code: 'missing_token', message: 'Access token is required' } },
        { status: 400 },
      );
    }
    const { sealedCookie, session } = createSealedSession(token, body?.user || null);
    const res = NextResponse.json({
      authenticated: true,
      csrf_token: session.csrfToken,
    });
    attachSessionCookie(res, sealedCookie);
    return res;
  } catch (err: any) {
    return NextResponse.json(
      { error: { code: 'bff_token_error', message: err?.message || 'Invalid request' } },
      { status: 400 },
    );
  }
}
