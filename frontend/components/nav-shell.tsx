"use client";

import type { ReactNode } from "react";

import { isDemoMode } from "../lib/api";
import AuthSessionStatus from "./auth-session-status";
import { ScopeProvider, useScope } from "./scope-context";
import ScopeSelector from "./scope-selector";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard" },
  { href: "/hierarchy", label: "Computers" },
  { href: "/clients", label: "Tenants" },
  { href: "/controls", label: "Deployments" },
  { href: "/approvals", label: "Sessions" },
  { href: "/installers", label: "Installers" },
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
  demoMode,
}: NavShellProps & { demoMode: boolean }) {
  const { href, scope } = useScope();

  return (
    <div className="shell">
      {demoMode ? (
        <div className="demo-banner" role="status">
          <strong>Demo mode</strong>
          <span>Invented fleet data. No real tenants or hosts, and changes are disabled.</span>
        </div>
      ) : null}

      <header className="command-header">
        <div className="brand-mark">
          <span className="brand-mark__code">SHA</span>
        </div>

        <div className="command-header__copy">
          <h1 title={description}>{title}</h1>
          <span aria-hidden="true" className="command-header__hint" title={description}>
            ?
          </span>
        </div>

        {actions ? <div className="command-header__actions">{actions}</div> : null}

        <div className="command-header__operator">
          <AuthSessionStatus
            demoMode={demoMode}
            scope={scopeAware ? scope : { client_id: null, location_id: null }}
          />
        </div>
      </header>

      <div className="console-bar">
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
                <span>{item.label}</span>
              </a>
            );
          })}
        </nav>
        {scopeAware ? <ScopeSelector /> : null}
      </div>

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
