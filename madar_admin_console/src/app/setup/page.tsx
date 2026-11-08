'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { bffFetch, setClientCsrfToken } from '@/lib/api-client';
import { FirstTimeSetupWizard } from '@/components/FirstTimeSetupWizard';

export default function SetupRoutePage() {
  const router = useRouter();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    let active = true;
    bffFetch('/admin-api/setup-status')
      .then((res) => {
        if (!active) return;
        // Once organization is registered, /setup is permanently locked and redirects to /
        if (res.data?.setup_completed) {
          router.replace('/');
        } else {
          setChecking(false);
        }
      })
      .catch(() => {
        if (active) setChecking(false);
      });
    return () => {
      active = false;
    };
  }, [router]);

  if (checking) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-300 flex items-center justify-center text-sm">
        Verifying workspace bootstrap state...
      </div>
    );
  }

  return (
    <FirstTimeSetupWizard
      onComplete={(payload) => {
        if (payload.csrf_token) {
          setClientCsrfToken(payload.csrf_token);
        }
        router.replace('/');
      }}
    />
  );
}
