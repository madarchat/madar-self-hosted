import { env } from '../config/env.js';
import { notFound } from '../lib/errors.js';

/**
 * ExtensionRegistry isolates Personal Social Extensions (Moments, Pulse, Waves/People,
 * Personal Invites, User Abuse Reports) from the Madar Core Engine.
 * When DEPLOYMENT_PROFILE === 'workspace', personal extensions are disabled and return 404.
 */
export class ExtensionRegistry {
  constructor() {
    /** @type {Map<string, { path: string, router: import('express').Router }>} */
    this.extensions = new Map();
  }

  /**
   * @param {string} name
   * @param {string} mountPath
   * @param {import('express').Router} router
   */
  register(name, mountPath, router) {
    this.extensions.set(name, { path: mountPath, router });
    return this;
  }

  isPersonalEnabled() {
    if (String(process.env.DISABLE_PERSONAL_EXTENSIONS || '').toLowerCase() === 'true') {
      return false;
    }
    if (this.activeProfile() === 'workspace') {
      return false;
    }
    return true;
  }

  activeProfile() {
    return (process.env.DEPLOYMENT_PROFILE || env.DEPLOYMENT_PROFILE || 'hybrid').toLowerCase();
  }

  activeExtensions() {
    if (!this.isPersonalEnabled()) return [];
    return [...this.extensions.keys()];
  }

  /**
   * Mounts registered extensions onto an Express router, guarded by deployment profile.
   * @param {import('express').Router} apiRouter
   */
  mountAll(apiRouter) {
    for (const [name, { path, router }] of this.extensions.entries()) {
      const guard = (req, _res, next) => {
        if (!this.isPersonalEnabled() || !router) {
          return next(
            notFound(
              'personal_extension_disabled',
              `Personal extension '${name}' is not mounted in '${this.activeProfile()}' profile (${req.method} ${req.originalUrl})`,
            ),
          );
        }
        return next();
      };
      if (router) {
        apiRouter.use(path, guard, router);
      } else {
        apiRouter.use(path, guard);
      }
    }
  }
}

export const extensionRegistry = new ExtensionRegistry();

/**
 * Registers and mounts all Personal Profile Extension routers onto the API router.
 */
export function registerPersonalExtensions(
  apiRouter,
  { peopleRouter, momentsRouter, pulseRouter, invitesRouter, reportsRouter } = {},
) {
  const reg = new ExtensionRegistry();
  reg.register('people', '/people', peopleRouter);
  reg.register('moments', '/moments', momentsRouter);
  reg.register('pulse', '/pulse', pulseRouter);
  reg.register('invites', '/invites', invitesRouter);
  reg.register('reports', '/reports', reportsRouter);
  reg.mountAll(apiRouter);
  return reg;
}

