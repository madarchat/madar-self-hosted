import { NextRequest, NextResponse } from 'next/server';
import QRCode from 'qrcode';

export const dynamic = 'force-dynamic';

/**
 * GET /admin-api/qr?data=...
 * Generates a self-contained SVG QR code on the server (zero external API leakage)
 * for Madar Agent enrollment URIs (madar://enroll?server=...&token=...).
 */
export async function GET(req: NextRequest) {
  const data = req.nextUrl.searchParams.get('data') || '';
  if (!data || data.length > 2048) {
    return NextResponse.json(
      { error: { code: 'invalid_qr_data', message: 'Valid QR payload required' } },
      { status: 400 },
    );
  }

  try {
    const svg = await QRCode.toString(data, {
      type: 'svg',
      margin: 2,
      width: 260,
      color: {
        dark: '#0f172a',
        light: '#ffffff',
      },
    });
    return new NextResponse(svg, {
      status: 200,
      headers: {
        'Content-Type': 'image/svg+xml; charset=utf-8',
        'Cache-Control': 'no-store',
      },
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: { code: 'qr_generation_failed', message: err?.message || 'QR error' } },
      { status: 500 },
    );
  }
}
