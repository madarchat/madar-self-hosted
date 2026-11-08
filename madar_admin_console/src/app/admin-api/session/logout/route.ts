import { NextResponse } from 'next/server';
import { clearSessionCookie } from '@/lib/bff-session';

export const dynamic = 'force-dynamic';

export async function POST() {
  const res = NextResponse.json({ authenticated: false });
  clearSessionCookie(res);
  return res;
}
