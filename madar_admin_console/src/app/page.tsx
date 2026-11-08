'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { useI18n } from '@/lib/i18n';
import { bffFetch, setClientCsrfToken } from '@/lib/api-client';
import { FirstTimeSetupWizard } from '@/components/FirstTimeSetupWizard';
import { AdminLoginView } from '@/components/AdminLoginView';
import { AdminDashboard } from '@/components/AdminDashboard';

export default function AdminConsoleHomePage() {
  const { t } = useI18n();
  const [bootState, setBootState] = useState<'loading' | 'setup' | 'login' | 'dashboard'>('loading');
  const [workspaceMeta, setWorkspaceMeta] = useState<{
    name?: string;
    primary_color?: string;
  }>({});
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [initialEnrollment, setInitialEnrollment] = useState<any>(null);
  const [justCompletedSetup, setJustCompletedSetup] = useState(false);

  const checkBootstrapAndSession = useCallback(async () => {
    setBootState('loading');
    try {
      const statusRes = await bffFetch('/admin-api/setup-status');
      const setupCompleted = Boolean(statusRes.data?.setup_completed);
      setWorkspaceMeta({
        name: statusRes.data?.workspace_name,
        primary_color: statusRes.data?.primary_color,
      });

      // 1. First-Time Deployment: Organization is not registered yet -> Show Setup Wizard
      if (!setupCompleted) {
        setBootState('setup');
        return;
      }

      // 2. Organization is already registered -> Never show setup wizard again; check session
      const sessionRes = await bffFetch('/admin-api/session');
      if (sessionRes.ok && sessionRes.data?.authenticated && sessionRes.data?.user) {
        if (sessionRes.data?.csrf_token) {
          setClientCsrfToken(sessionRes.data.csrf_token);
        }
        setCurrentUser(sessionRes.data.user);
        setBootState('dashboard');
      } else {
        setBootState('login');
      }
    } catch {
      setBootState('login');
    }
  }, []);

  useEffect(() => {
    checkBootstrapAndSession();
  }, [checkBootstrapAndSession]);

  const handleLogout = async () => {
    await bffFetch('/admin-api/session/logout', { method: 'POST', body: {} });
    setClientCsrfToken(null);
    setCurrentUser(null);
    setJustCompletedSetup(false);
    setBootState('login');
  };

  if (bootState === 'loading') {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6">
        <div className="w-12 h-12 rounded-2xl bg-teal-500 flex items-center justify-center font-bold text-slate-950 text-xl animate-pulse mb-4">
          M
        </div>
        <p className="text-sm font-medium text-slate-300">{t.loading}</p>
      </div>
    );
  }

  if (bootState === 'setup') {
    return (
      <FirstTimeSetupWizard
        onComplete={(payload) => {
          if (payload.csrf_token) {
            setClientCsrfToken(payload.csrf_token);
          }
          if (payload.initial_enrollment) {
            setInitialEnrollment(payload.initial_enrollment);
          }
          setJustCompletedSetup(true);
          if (payload.authenticated && payload.user) {
            setCurrentUser(payload.user);
            setBootState('dashboard');
          } else {
            checkBootstrapAndSession();
          }
        }}
      />
    );
  }

  if (bootState === 'login') {
    return (
      <AdminLoginView
        workspaceName={workspaceMeta.name}
        primaryColor={workspaceMeta.primary_color}
        onLoginSuccess={(payload) => {
          if (payload.csrf_token) {
            setClientCsrfToken(payload.csrf_token);
          }
          setCurrentUser(payload.user);
          setBootState('dashboard');
        }}
      />
    );
  }

  return (
    <AdminDashboard
      currentUser={currentUser}
      initialEnrollment={initialEnrollment}
      justCompletedSetup={justCompletedSetup}
      onLogout={handleLogout}
    />
  );
}
