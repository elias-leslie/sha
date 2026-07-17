"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";

import {
  createClient,
  createLocation,
  getFixtureLocations,
  isDemoMode,
  listLocations,
  type Location,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader } from "./console-primitives";
import { hierarchyDisplayName, useScope } from "./scope-context";

export default function ClientsConsole({ demoMode = isDemoMode() }: { demoMode?: boolean }) {
  const { scope, clients, loading, error: hierarchyError, refreshHierarchy } = useScope();
  const lastAppliedScopeClientId = useRef<string | null>(null);
  const [selectedClientId, setSelectedClientId] = useState("");
  const [locations, setLocations] = useState<Location[]>([]);
  const [clientForm, setClientForm] = useState({ key: "tenant-new", name: "New client" });
  const [locationForm, setLocationForm] = useState({ key: "site-main", name: "Main location" });
  const [pending, setPending] = useState<"client" | "location" | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const selectedClient = clients.find((client) => client.client_id === selectedClientId) ?? null;
  const canCreateLocation = Boolean(
    selectedClient?.state === "active" && !selectedClient.is_system,
  );

  useEffect(() => {
    if (
      scope.client_id &&
      scope.client_id !== lastAppliedScopeClientId.current &&
      clients.some((client) => client.client_id === scope.client_id)
    ) {
      lastAppliedScopeClientId.current = scope.client_id;
      setSelectedClientId(scope.client_id);
      return;
    }
    if (!scope.client_id) {
      lastAppliedScopeClientId.current = null;
    }
    if (
      clients.length &&
      !clients.some((client) => client.client_id === selectedClientId)
    ) {
      setSelectedClientId(clients.find((client) => !client.is_system)?.client_id ?? clients[0].client_id);
    }
  }, [clients, scope.client_id, selectedClientId]);

  useEffect(() => {
    if (!selectedClientId) {
      setLocations([]);
      return;
    }
    if (demoMode) {
      setLocations(getFixtureLocations(selectedClientId));
      return;
    }
    let cancelled = false;
    listLocations(selectedClientId)
      .then((items) => {
        if (!cancelled) {
          setLocations(items);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setLocations([]);
          setError(caught instanceof Error ? caught.message : "Unable to load locations.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [demoMode, selectedClientId]);

  async function handleCreateClient(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (demoMode) {
      return;
    }
    setPending("client");
    setMessage(null);
    setError(null);
    try {
      const created = await createClient(clientForm);
      await refreshHierarchy();
      setSelectedClientId(created.client_id);
      setMessage(`Created client ${created.name}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create client.");
    } finally {
      setPending(null);
    }
  }

  async function handleCreateLocation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (demoMode || !selectedClientId || !canCreateLocation) {
      return;
    }
    setPending("location");
    setMessage(null);
    setError(null);
    try {
      const created = await createLocation(selectedClientId, locationForm);
      setLocations((current) => [...current, created]);
      await refreshHierarchy();
      setMessage(`Created location ${created.name}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create location.");
    } finally {
      setPending(null);
    }
  }

  return (
    <>
      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Ownership hierarchy"
            title="Clients"
            description="Canonical client boundaries. Compatibility tenant keys remain immutable aliases."
          />
          {clients.length ? (
            <div className="card-grid">
              {clients.map((client) => (
                <button
                  className="mini-card mini-card--interactive"
                  data-active={selectedClientId === client.client_id ? "true" : "false"}
                  key={client.client_id}
                  onClick={() => setSelectedClientId(client.client_id)}
                  type="button"
                >
                  <div className="operator-list__title-row">
                    <strong>{client.name}</strong>
                    <Badge tone={client.state === "active" ? "success" : "warning"}>
                      {client.state === "migration_quarantine"
                        ? "Migration quarantine"
                        : client.state === "archived"
                          ? "Archived"
                          : "Active"}
                    </Badge>
                  </div>
                  <p>{client.key ?? "No compatibility key"}</p>
                  <p>{client.client_id}</p>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState
              title={loading ? "Loading client hierarchy" : "No clients"}
              body="Create the first client boundary before assigning production installer profiles."
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Create client"
            title="New ownership boundary"
            description="Keys are immutable compatibility aliases. Names remain operator-facing labels."
          />
          <form className="form-grid" onSubmit={handleCreateClient}>
            <label className="field" htmlFor="new-client-key">
              <span className="field__label">Client key</span>
              <input
                className="field__control"
                id="new-client-key"
                onChange={(event) => setClientForm((current) => ({ ...current, key: event.target.value }))}
                required
                value={clientForm.key}
              />
            </label>
            <label className="field" htmlFor="new-client-name">
              <span className="field__label">Client name</span>
              <input
                className="field__control"
                id="new-client-name"
                onChange={(event) => setClientForm((current) => ({ ...current, name: event.target.value }))}
                required
                value={clientForm.name}
              />
            </label>
            <div className="form-actions">
              <button
                className="action-button action-button--primary"
                disabled={demoMode || pending !== null}
                type="submit"
              >
                {demoMode ? "Creation disabled in demo" : pending === "client" ? "Creating…" : "Create client"}
              </button>
            </div>
          </form>
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Selected client"
            title="Locations"
            description="Each endpoint belongs to one location beneath one client."
          />
          {locations.length ? (
            <div className="card-grid">
              {locations.map((location) => (
                <article className="mini-card" key={location.location_id}>
                  <div className="operator-list__title-row">
                    <strong>{hierarchyDisplayName(location)}</strong>
                    <Badge tone={location.state === "active" ? "success" : "warning"}>
                      {location.state === "migration_quarantine"
                        ? "Migration quarantine"
                        : location.state === "archived"
                          ? "Archived"
                          : "Active"}
                    </Badge>
                  </div>
                  <p>{location.key ?? "No compatibility key"}</p>
                  <p>{location.location_id}</p>
                </article>
              ))}
            </div>
          ) : (
            <EmptyState
              title={selectedClientId ? "No locations" : "Select a client"}
              body="Select a client, then create its first operational location."
            />
          )}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Create location"
            title="New site boundary"
            description="Location keys are unique within the selected client."
          />
          <form className="form-grid" onSubmit={handleCreateLocation}>
            <label className="field" htmlFor="location-client">
              <span className="field__label">Parent client</span>
              <select
                className="field__control"
                id="location-client"
                onChange={(event) => setSelectedClientId(event.target.value)}
                required
                value={selectedClientId}
              >
                <option value="">Select a client</option>
                {clients.map((client) => (
                  <option key={client.client_id} value={client.client_id}>
                    {hierarchyDisplayName(client)}
                  </option>
                ))}
              </select>
            </label>
            <label className="field" htmlFor="new-location-key">
              <span className="field__label">Location key</span>
              <input
                className="field__control"
                id="new-location-key"
                onChange={(event) => setLocationForm((current) => ({ ...current, key: event.target.value }))}
                required
                value={locationForm.key}
              />
            </label>
            <label className="field field--span-2" htmlFor="new-location-name">
              <span className="field__label">Location name</span>
              <input
                className="field__control"
                id="new-location-name"
                onChange={(event) => setLocationForm((current) => ({ ...current, name: event.target.value }))}
                required
                value={locationForm.name}
              />
            </label>
            <div className="form-actions">
              <button
                className="action-button action-button--primary"
                disabled={demoMode || pending !== null || !canCreateLocation}
                type="submit"
              >
                {demoMode ? "Creation disabled in demo" : pending === "location" ? "Creating…" : "Create location"}
              </button>
              {message ? <span className="inline-feedback inline-feedback--success">{message}</span> : null}
              {selectedClientId && !canCreateLocation ? (
                <span className="inline-feedback inline-feedback--danger">
                  Locations cannot be created beneath archived, system, or migration-quarantine clients.
                </span>
              ) : null}
              {error || hierarchyError ? (
                <span className="inline-feedback inline-feedback--danger">{error ?? hierarchyError}</span>
              ) : null}
            </div>
          </form>
        </Panel>
      </section>
    </>
  );
}
