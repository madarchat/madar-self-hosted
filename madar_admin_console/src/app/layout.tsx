import type { Metadata } from 'next';
import './globals.css';
import { I18nProvider } from '@/lib/i18n';

export const metadata: Metadata = {
  title: 'Madar Sovereign Admin Console',
  description:
    'Isolated Enterprise Control-Plane BFF for Madar Self-Hosted Sovereign Workspace (Zero Direct DB Access)',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased">
        <I18nProvider>{children}</I18nProvider>
      </body>
    </html>
  );
}
