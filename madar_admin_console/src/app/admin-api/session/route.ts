import { NextRequest, NextResponse } from 'next/server';
import { readSessionFromRequest } from '@/lib/bff-session';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const session = readSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ authenticated: false });
  }
  return NextResponse.json({
    authenticated: true,
    csrf_token: session.csrfToken,
    user: session.user,
  });
}
