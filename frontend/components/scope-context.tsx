"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import {
  getFixtureClients,
  getFixtureLocations,
  listClients,
  listLocations,
  scopeHref,
  type Client,
  type Location,
  type ScopeSelection,
} from "../lib/api";

type ScopeContextValue = {
  scope: ScopeSelection;
  clients: Client[];
  locations: Location[];
  selectedClient: Client | null;
  selectedLocation: Location | null;
  ready: boolean;
  loading: boolean;
  error: string | null;
  setScope: (scope: ScopeSelection) => void;
  refreshHierarchy: () => Promise<void>;
  href: (path: string) => string;
};

const GLOBAL_SCOPE: ScopeSelection = { client_id: null, location_id: null };
const ScopeContext = createContext<ScopeContextValue | null>(null);

function readUrlScope(): ScopeSelection {
  if (typeof window === "undefined") {
    return GLOBAL_SCOPE;
  }
  const params = new URLSearchParams(window.location.search);
  const clientId = params.get("client_id")?.trim() || null;
  return {
    client_id: clientId,
    location_id: clientId ? params.get("location_id")?.trim() || null : null,
  };
}

function writeUrlScope(scope: ScopeSelection) {
  if (typeof window === "undefined") {
    return;
  }
  const url = new URL(window.location.href);
  const currentClient = url.searchParams.get("client_id")?.trim() || null;
  const currentLocation = url.searchParams.get("location_id")?.trim() || null;
  const targetClient = scope.client_id || null;
  const targetLocation = scope.location_id || null;

  if (currentClient === targetClient && currentLocation === targetLocation) {
    return;
  }

  if (targetClient) {
    url.searchParams.set("client_id", targetClient);
    if (targetLocation) {
      url.searchParams.set("location_id", targetLocation);
    } else {
      url.searchParams.delete("location_id");
    }
  } else {
    url.searchParams.delete("client_id");
    url.searchParams.delete("location_id");
  }
  window.history.replaceState({}, "", url.toString());
}

export function hierarchyDisplayName(item: Client | Location) {
  if (item.state === "migration_quarantine") {
    return `${item.name} — migration quarantine`;
  }
  if (item.state === "archived") {
    return `${item.name} — archived`;
  }
  return item.name;
}

export function ScopeProvider({ children, demoMode }: { children: ReactNode; demoMode: boolean }) {
  const [scope, setScopeState] = useState<ScopeSelection>(GLOBAL_SCOPE);
  const [initialized, setInitialized] = useState(false);
  const [scopeReady, setScopeReady] = useState(false);
  const [clients, setClients] = useState<Client[]>(() => (demoMode ? getFixtureClients() : []));
  const [locations, setLocations] = useState<Location[]>([]);
  const [loading, setLoading] = useState(!demoMode);
  const [error, setError] = useState<string | null>(null);
  const requestGeneration = useRef(0);

  const refreshHierarchy = useCallback(async () => {
    const requestId = ++requestGeneration.current;
    setLoading(true);
    setScopeReady(false);
    setLocations([]);
    setError(null);
    try {
      const nextClients = demoMode ? getFixtureClients() : await listClients();
      if (requestId !== requestGeneration.current) {
        return;
      }
      setClients(nextClients);

      let nextScope = scope;
      let nextLocations: Location[] = [];
      let canonicalizationMessage: string | null = null;
      const selectedClient = scope.client_id
        ? nextClients.find((client) => client.client_id === scope.client_id)
        : null;

      if (scope.client_id && !selectedClient) {
        nextScope = GLOBAL_SCOPE;
        canonicalizationMessage = "Unknown client scope was cleared.";
      } else if (scope.client_id) {
        nextLocations = demoMode
          ? getFixtureLocations(scope.client_id)
          : await listLocations(scope.client_id);
        if (requestId !== requestGeneration.current) {
          return;
        }
        if (
          scope.location_id &&
          !nextLocations.some(
            (location) =>
              location.location_id === scope.location_id &&
              location.client_id === scope.client_id,
          )
        ) {
          nextScope = { client_id: scope.client_id, location_id: null };
          canonicalizationMessage = "Unknown or mismatched location scope was cleared.";
        }
      }

      if (requestId !== requestGeneration.current) {
        return;
      }
      setLocations(nextScope.client_id ? nextLocations : []);
      if (
        nextScope.client_id !== scope.client_id ||
        nextScope.location_id !== scope.location_id
      ) {
        setScopeState(nextScope);
        writeUrlScope(nextScope);
      }
      setError(canonicalizationMessage);
      setScopeReady(true);
    } catch (caught) {
      if (requestId === requestGeneration.current) {
        setClients([]);
        setLocations([]);
        setError(caught instanceof Error ? caught.message : "Unable to load client hierarchy.");
      }
    } finally {
      if (requestId === requestGeneration.current) {
        setLoading(false);
      }
    }
  }, [demoMode, scope]);

  useEffect(() => {
    const syncFromUrl = () => {
      requestGeneration.current += 1;
      setScopeState(readUrlScope());
      setLocations([]);
      setScopeReady(false);
      setInitialized(true);
    };
    syncFromUrl();
    window.addEventListener("popstate", syncFromUrl);
    return () => window.removeEventListener("popstate", syncFromUrl);
  }, []);

  useEffect(() => {
    if (!initialized) {
      return;
    }
    void refreshHierarchy();
  }, [initialized, refreshHierarchy]);

  const setScope = useCallback((nextScope: ScopeSelection) => {
    const normalized = nextScope.client_id
      ? {
          client_id: nextScope.client_id,
          location_id: nextScope.location_id || null,
        }
      : GLOBAL_SCOPE;
    requestGeneration.current += 1;
    setLocations([]);
    setScopeReady(false);
    setScopeState(normalized);
    writeUrlScope(normalized);
  }, []);

  const selectedClient = clients.find((client) => client.client_id === scope.client_id) ?? null;
  const selectedLocation =
    locations.find((location) => location.location_id === scope.location_id) ?? null;
  const href = useCallback((path: string) => scopeHref(path, scope), [scope]);
  const value = useMemo<ScopeContextValue>(
    () => ({
      scope,
      clients,
      locations,
      selectedClient,
      selectedLocation,
      ready: scopeReady,
      loading,
      error,
      setScope,
      refreshHierarchy,
      href,
    }),
    [
      scope,
      clients,
      locations,
      selectedClient,
      selectedLocation,
      scopeReady,
      loading,
      error,
      setScope,
      refreshHierarchy,
      href,
    ],
  );

  return <ScopeContext.Provider value={value}>{children}</ScopeContext.Provider>;
}

export function useScope() {
  const context = useContext(ScopeContext);
  if (!context) {
    throw new Error("useScope must be used within ScopeProvider");
  }
  return context;
}
