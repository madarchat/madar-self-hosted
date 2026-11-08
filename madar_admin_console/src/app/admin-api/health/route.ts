import { NextResponse } from 'next/server';
import { getUpstreamBaseUrl } from '@/lib/bff-session';

export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json({
    status: 'ok',
    service: 'madar-admin-console-bff',
    framework: 'nextjs-app-router',
    isolated: true,
    isolated_control_plane: true,
    zero_db_access: true,
    direct_db_access: false,
    upstream_url: getUpstreamBaseUrl(),
  });
}
