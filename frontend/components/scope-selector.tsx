"use client";

import { hierarchyDisplayName, useScope } from "./scope-context";

export default function ScopeSelector() {
  const {
    scope,
    clients,
    locations,
    selectedClient,
    selectedLocation,
    ready,
    loading,
    error,
    setScope,
  } = useScope();
  const quarantined =
    selectedClient?.state === "migration_quarantine" ||
    selectedLocation?.state === "migration_quarantine";
  const archived =
    selectedClient?.state === "archived" || selectedLocation?.state === "archived";
  const clientLabel = selectedClient?.name ?? null;
  const locationLabel = selectedLocation?.name ?? null;

  return (
    <section aria-label="Scope selector" className="scope-selector">
      <div className="scope-selector__copy">
        <span className="brand-mark__eyebrow">Active viewpoint</span>
        <strong>
          {!ready
            ? loading
              ? "Validating selected scope…"
              : "Selected scope unavailable"
            : clientLabel
            ? `${clientLabel}${locationLabel ? ` / ${locationLabel}` : " / All locations"}`
            : "Global / All clients"}
        </strong>
      </div>
      <label className="field" htmlFor="scope-client">
        <span className="field__label">Client scope</span>
        <select
          className="field__control"
          disabled={loading}
          id="scope-client"
          onChange={(event) =>
            setScope({
              client_id: event.target.value || null,
              location_id: null,
            })
          }
          value={scope.client_id ?? ""}
        >
          <option value="">All clients</option>
          {clients.map((client) => (
            <option key={client.client_id} value={client.client_id}>
              {hierarchyDisplayName(client)}
            </option>
          ))}
        </select>
      </label>
      <label className="field" htmlFor="scope-location">
        <span className="field__label">Location scope</span>
        <select
          className="field__control"
          disabled={loading || !scope.client_id}
          id="scope-location"
          onChange={(event) =>
            setScope({
              client_id: scope.client_id,
              location_id: event.target.value || null,
            })
          }
          value={scope.location_id ?? ""}
        >
          <option value="">All locations</option>
          {locations.map((location) => (
            <option key={location.location_id} value={location.location_id}>
              {hierarchyDisplayName(location)}
            </option>
          ))}
        </select>
      </label>
      {quarantined ? <span className="tone tone--warning">Migration quarantine</span> : null}
      {archived ? <span className="tone tone--warning">Archived scope</span> : null}
      {error ? <span className="inline-feedback inline-feedback--danger">Hierarchy: {error}</span> : null}
    </section>
  );
}
