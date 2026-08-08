"use client";

import { useEffect, useMemo, useState } from "react";

import {
  ApiRequestError,
  clearAuthSessionCache,
  getAuthSession,
  logoutAllSessions,
  logoutCurrentSession,
  safeReturnPath,
  subscribeAuthSession,
  type AuthScopeBinding,
  type AuthSession,
  type ScopeSelection,
} from "../lib/api";

type AuthView = "loading" | "authenticated" | "unauthenticated" | "denied" | "error";

function bindingApplies(binding: AuthScopeBinding, scope: ScopeSelection) {
  if (binding.scope_type === "global") {
    return true;
  }
  if (binding.scope_type === "client") {
    return Boolean(scope.client_id && binding.client_id === scope.client_id);
  }
  return Boolean(
    scope.client_id &&
      scope.location_id &&
      binding.client_id === scope.client_id &&
      binding.location_id === scope.location_id,
  );
}

function bindingLabel(binding: AuthScopeBinding) {
  if (binding.scope_type === "global") {
    return `${binding.role} · global`;
  }
  if (binding.scope_type === "client") {
    return `${binding.role} · client ${binding.client_id}`;
  }
  return `${binding.role} · location ${binding.location_id}`;
}

function currentReturnPath() {
  if (typeof window === "undefined") {
    return "/";
  }
  return safeReturnPath(`${window.location.pathname}${window.location.search}${window.location.hash}`);
}

export default function AuthSessionStatus({
  demoMode,
  scope,
}: {
  demoMode: boolean;
  scope: ScopeSelection;
}) {
  const [view, setView] = useState<AuthView>(demoMode ? "authenticated" : "loading");
  const [session, setSession] = useState<AuthSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"logout" | "logout-all" | null>(null);
  const [loginHref, setLoginHref] = useState("/api/auth/oidc/login?return_to=%2F");

  useEffect(() => {
    setLoginHref(`/api/auth/oidc/login?${new URLSearchParams({ return_to: currentReturnPath() })}`);
    if (demoMode) {
      return;
    }

    let active = true;
    const unsubscribe = subscribeAuthSession((nextSession) => {
      if (!active) {
        return;
      }
      setSession(nextSession);
      setError(null);
      setView(nextSession ? "authenticated" : "unauthenticated");
    });
    getAuthSession({ refresh: true })
      .then((nextSession) => {
        if (!active) {
          return;
        }
        setSession(nextSession);
        setView(nextSession ? "authenticated" : "unauthenticated");
      })
      .catch((reason: unknown) => {
        if (!active) {
          return;
        }
        setError(
          reason instanceof ApiRequestError && reason.status === 403
            ? reason.message
            : reason instanceof ApiRequestError
              ? `Session check failed with status ${reason.status}.`
              : "Authentication status is unavailable.",
        );
        setView(reason instanceof ApiRequestError && reason.status === 403 ? "denied" : "error");
      });

    return () => {
      active = false;
      unsubscribe();
    };
  }, [demoMode]);

  const effectiveBindings = useMemo(
    () => session?.bindings.filter((binding) => bindingApplies(binding, scope)) ?? [],
    [scope, session],
  );

  async function signOut(allSessions: boolean) {
    setBusy(allSessions ? "logout-all" : "logout");
    setError(null);
    try {
      if (allSessions) {
        await logoutAllSessions();
      } else {
        await logoutCurrentSession();
      }
      clearAuthSessionCache();
      setSession(null);
      setView("unauthenticated");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sign out failed.");
    } finally {
      setBusy(null);
    }
  }

  if (demoMode) {
    return (
      <section aria-label="Authentication" className="auth-session auth-session--demo">
        <span className="brand-mark__eyebrow">Demo identity</span>
        <strong>Fixture operator · no live authority</strong>
      </section>
    );
  }

  if (view === "loading") {
    return (
      <section aria-label="Authentication" className="auth-session">
        <span className="brand-mark__eyebrow">Identity</span>
        <strong>Checking session…</strong>
      </section>
    );
  }

  if (view === "unauthenticated") {
    return (
      <section aria-label="Authentication" className="auth-session auth-session--warning">
        <div>
          <span className="brand-mark__eyebrow">Not signed in</span>
          <p>Live data and actions require an operator identity.</p>
        </div>
        <a className="action-button action-button--primary auth-session__button" href={loginHref}>
          Sign in
        </a>
      </section>
    );
  }

  if (view === "denied") {
    return (
      <section aria-label="Authentication" className="auth-session auth-session--danger">
        <div>
          <span className="brand-mark__eyebrow">Access denied</span>
          <p>{error ?? "Current identity cannot access this control plane."}</p>
        </div>
      </section>
    );
  }

  if (view === "error" || !session) {
    return (
      <section aria-label="Authentication" className="auth-session auth-session--danger">
        <div>
          <span className="brand-mark__eyebrow">Authentication unavailable</span>
          <p>{error ?? "Could not verify the current session."}</p>
        </div>
        <a className="action-button action-button--secondary auth-session__button" href={loginHref}>
          Sign in
        </a>
      </section>
    );
  }

  const pending = session.status !== "active";
  const zeroAuthority = pending || session.bindings.length === 0;
  return (
    <section
      aria-label="Authentication"
      className={`auth-session${zeroAuthority ? " auth-session--warning" : ""}`}
    >
      <div className="auth-session__identity">
        <span className="brand-mark__eyebrow">Operator</span>
        <strong>{session.display_name}</strong>
        <span>{session.subject}</span>
      </div>
      <div className="auth-session__authority">
        <span className="brand-mark__eyebrow">Role</span>
        {pending ? (
          <strong>Pending identity</strong>
        ) : effectiveBindings.length ? (
          <div className="auth-session__bindings">
            {effectiveBindings.map((binding) => (
              <span className="tone tone--info" key={binding.binding_id}>
                {binding.role === "DEVELOPMENT_ADMIN" ? "Admin (Global)" : bindingLabel(binding)}
              </span>
            ))}
          </div>
        ) : (
          <span className="tone tone--info">Admin (Global)</span>
        )}
      </div>
      {session.authentication_method === "oidc_session" ? (
        <div className="auth-session__actions">
          <button
            className="action-button action-button--ghost auth-session__button"
            disabled={busy !== null}
            onClick={() => void signOut(false)}
            type="button"
          >
            {busy === "logout" ? "Signing out…" : "Sign out"}
          </button>
          <button
            className="action-button action-button--ghost auth-session__button"
            disabled={busy !== null}
            onClick={() => void signOut(true)}
            type="button"
          >
            {busy === "logout-all" ? "Signing out…" : "Sign out all"}
          </button>
        </div>
      ) : null}
      {error ? <p className="inline-feedback inline-feedback--danger" role="alert">{error}</p> : null}
    </section>
  );
}
