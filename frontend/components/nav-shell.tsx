"use client";

import type { ReactNode } from "react";

import { isDemoMode } from "../lib/api";
import AuthSessionStatus from "./auth-session-status";
import { ScopeProvider, useScope } from "./scope-context";
import ScopeSelector from "./scope-selector";

const NAV_ITEMS = [
  { href: "/", label: "Home", code: "OVR" },
  { href: "/fleet", label: "Fleet", code: "FLT" },
  { href: "/clients", label: "Clients", code: "CLI" },
  { href: "/controls", label: "Controls", code: "CTL" },
  { href: "/approvals", label: "Approvals", code: "APR" },
  { href: "/installers", label: "Installers", code: "PKG" },
] as const;

type NavShellProps = {
  currentPath?: string;
  title: ReactNode;
  description: string;
  children: ReactNode;
  actions?: ReactNode;
  scopeAware?: boolean;
  scopeNotice?: string;
};

function NavShellContent({
  currentPath = "/",
  title,
  description,
  children,
  actions,
  scopeAware = false,
  scopeNotice = "Global-only view. Client and location selection does not filter or authorize this page.",
  demoMode,
}: NavShellProps & { demoMode: boolean }) {
  const { href, scope } = useScope();

  return (
    <div className="shell">
      {demoMode ? (
        <div className="inline-feedback inline-feedback--danger" role="status">
          Demo mode — fixture data only. Live mutations disabled.
        </div>
      ) : null}
      <header className="command-header">
        <div className="command-header__topline">
          <div className="brand-mark">
            <span className="brand-mark__code">SHA</span>
            <div>
              <p className="brand-mark__eyebrow">Security Hardening Automation</p>
              <p className="brand-mark__meta">operator supervised autonomy • same-origin api routing</p>
            </div>
          </div>
          <div className="command-header__operator">
            <AuthSessionStatus
              demoMode={demoMode}
              scope={scopeAware ? scope : { client_id: null, location_id: null }}
            />
            <div className="command-header__badges">
              <span className="tone tone--success">Public edge</span>
              <span className="tone tone--warning">Operator supervised autonomy</span>
              <span className="tone tone--info">Dark amber containment rail</span>
            </div>
          </div>
        </div>

        <div className="command-header__main">
          <div className="command-header__copy">
            <p className="command-header__eyebrow">Security control plane</p>
            <h1>{title}</h1>
            <p className="command-header__description">{description}</p>
          </div>
          {actions ? <div className="command-header__actions">{actions}</div> : null}
        </div>
      </header>

      {scopeAware ? (
        <ScopeSelector />
      ) : (
        <section aria-label="Scope applicability" className="scope-notice">
          <span className="brand-mark__eyebrow">Scope applicability</span>
          <strong>{scopeNotice}</strong>
          {scope.client_id ? (
            <p>Selected client and location context remains in navigation for Fleet and Installers.</p>
          ) : null}
        </section>
      )}

      <nav aria-label="Primary" className="primary-nav">
        {NAV_ITEMS.map((item) => {
          const isActive = currentPath === item.href;
          return (
            <a
              key={item.href}
              className="nav-link"
              data-active={isActive ? "true" : "false"}
              href={href(item.href)}
            >
              <span aria-hidden="true" className="nav-link__code">{item.code}</span>
              <span>{item.label}</span>
            </a>
          );
        })}
      </nav>

      <main className="shell-main">{children}</main>
    </div>
  );
}

export default function NavShell(props: NavShellProps) {
  const demoMode = isDemoMode();
  return (
    <ScopeProvider demoMode={demoMode}>
      <NavShellContent {...props} demoMode={demoMode} />
    </ScopeProvider>
  );
}
