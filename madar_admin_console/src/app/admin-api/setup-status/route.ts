import { NextRequest, NextResponse } from 'next/server';
import { forwardUpstream, readSessionFromRequest } from '@/lib/bff-session';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const discovery = await forwardUpstream('GET', '/.well-known/madar-workspace.json');
    const session = readSessionFromRequest(req);

    return NextResponse.json({
      setup_completed: Boolean(discovery.data?.setup_completed),
      workspace: discovery.data || null,
      authenticated: Boolean(session),
      csrf_token: session?.csrfToken || null,
      user: session?.user || null,
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        setup_completed: false,
        workspace: null,
        authenticated: false,
        upstream_unreachable: true,
        error: err?.message || 'Cannot reach Madar Core Server',
      },
      { status: 200 },
    );
  }
}
