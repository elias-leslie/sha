"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";

import {
  assignEndpointTag,
  createDynamicGroup,
  createSavedView,
  createTag,
  isDemoMode,
  listDynamicGroups,
  listEndpoints,
  listEndpointTags,
  listSavedViews,
  listTags,
  previewDynamicGroup,
  removeEndpointTag,
  type AssignedEndpointTag,
  type DynamicGroup,
  type DynamicGroupPreview,
  type EndpointInventoryItem,
  type EndpointTag,
  type FleetResourceScope,
  type Platform,
  type SavedView,
} from "../lib/api";
import { Badge, EmptyState, Panel, SectionHeader, StatCard } from "./console-primitives";
import { useScope } from "./scope-context";

function selectedResourceScope(
  clientId: string | null,
  locationId: string | null,
): FleetResourceScope {
  if (clientId && locationId) {
    return { scope_type: "location", client_id: clientId, location_id: locationId };
  }
  if (clientId) {
    return { scope_type: "client", client_id: clientId, location_id: null };
  }
  return { scope_type: "global", client_id: null, location_id: null };
}

function scopeLabel(resource: FleetResourceScope) {
  if (resource.scope_type === "global") {
    return "Global";
  }
  if (resource.scope_type === "client") {
    return `Client ${resource.client_id}`;
  }
  return `Location ${resource.location_id}`;
}

export default function FleetMetadataConsole() {
  const demoMode = isDemoMode();
  const { scope, ready } = useScope();
  const resourceScope = useMemo(
    () => selectedResourceScope(scope.client_id, scope.location_id),
    [scope.client_id, scope.location_id],
  );
  const [tags, setTags] = useState<EndpointTag[]>([]);
  const [views, setViews] = useState<SavedView[]>([]);
  const [groups, setGroups] = useState<DynamicGroup[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointInventoryItem[]>([]);
  const [assignedTags, setAssignedTags] = useState<AssignedEndpointTag[]>([]);
  const [selectedEndpointId, setSelectedEndpointId] = useState("");
  const [selectedTagId, setSelectedTagId] = useState("");
  const [preview, setPreview] = useState<DynamicGroupPreview | null>(null);
  const [loading, setLoading] = useState(!demoMode);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tagName, setTagName] = useState("");
  const [viewName, setViewName] = useState("");
  const [viewPlatform, setViewPlatform] = useState<Platform>("linux");
  const [viewVisibility, setViewVisibility] = useState<"private" | "shared">("shared");
  const [groupName, setGroupName] = useState("");
  const [groupViewId, setGroupViewId] = useState("");

  useEffect(() => {
    if (!ready || demoMode) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      listTags(scope),
      listSavedViews(scope),
      listDynamicGroups(scope),
      listEndpoints(scope),
    ])
      .then(([nextTags, nextViews, nextGroups, nextEndpoints]) => {
        if (cancelled) {
          return;
        }
        setTags(nextTags);
        setViews(nextViews);
        setGroups(nextGroups);
        setEndpoints(nextEndpoints);
        setSelectedEndpointId((current) =>
          nextEndpoints.some((endpoint) => endpoint.endpoint_id === current)
            ? current
            : (nextEndpoints[0]?.endpoint_id ?? ""),
        );
        setSelectedTagId((current) =>
          nextTags.some((tag) => tag.tag_id === current) ? current : (nextTags[0]?.tag_id ?? ""),
        );
        setGroupViewId((current) =>
          nextViews.some((view) => view.saved_view_id === current)
            ? current
            : (nextViews[0]?.saved_view_id ?? ""),
        );
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Fleet metadata is unavailable.");
          setTags([]);
          setViews([]);
          setGroups([]);
          setEndpoints([]);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [demoMode, ready, scope.client_id, scope.location_id]);

  useEffect(() => {
    if (!selectedEndpointId || demoMode) {
      setAssignedTags([]);
      return;
    }
    let cancelled = false;
    listEndpointTags(selectedEndpointId)
      .then((items) => {
        if (!cancelled) {
          setAssignedTags(items);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setAssignedTags([]);
          setError(caught instanceof Error ? caught.message : "Endpoint tags are unavailable.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [demoMode, selectedEndpointId]);

  async function runMutation(work: () => Promise<void>) {
    setPending(true);
    setError(null);
    setMessage(null);
    try {
      await work();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Fleet metadata change failed.");
    } finally {
      setPending(false);
    }
  }

  function handleCreateTag(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runMutation(async () => {
      const created = await createTag({
        ...resourceScope,
        name: tagName,
      });
      setTags((current) => [...current, created].sort((left, right) => left.name.localeCompare(right.name)));
      setSelectedTagId(created.tag_id);
      setTagName("");
      setMessage(`Tag ${created.name} created at ${scopeLabel(created)} scope.`);
    });
  }

  function handleAssignTag(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedEndpointId || !selectedTagId) {
      return;
    }
    void runMutation(async () => {
      const assigned = await assignEndpointTag(selectedEndpointId, selectedTagId);
      setAssignedTags((current) => [
        ...current.filter((item) => item.tag_id !== assigned.tag_id),
        assigned,
      ]);
      setMessage(`Tag ${assigned.name} assigned.`);
    });
  }

  function handleRemoveTag(tag: AssignedEndpointTag) {
    if (!selectedEndpointId) {
      return;
    }
    void runMutation(async () => {
      await removeEndpointTag(selectedEndpointId, tag.tag_id);
      setAssignedTags((current) => current.filter((item) => item.tag_id !== tag.tag_id));
      setMessage(`Tag ${tag.name} removed.`);
    });
  }

  function handleCreateView(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runMutation(async () => {
      const created = await createSavedView({
        ...resourceScope,
        name: viewName,
        visibility: viewVisibility,
        filter: {
          schema_version: 1,
          match: "all",
          rules: [{ field: "platform", op: "eq", value: viewPlatform }],
        },
      });
      setViews((current) => [...current, created].sort((left, right) => left.name.localeCompare(right.name)));
      setGroupViewId(created.saved_view_id);
      setViewName("");
      setMessage(`Saved view ${created.name} created as version 1.`);
    });
  }

  function handleCreateGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!groupViewId) {
      return;
    }
    void runMutation(async () => {
      const created = await createDynamicGroup({
        name: groupName,
        saved_view_id: groupViewId,
      });
      setGroups((current) => [...current, created].sort((left, right) => left.name.localeCompare(right.name)));
      setGroupName("");
      setMessage(`Dynamic group ${created.name} created.`);
    });
  }

  function handlePreview(group: DynamicGroup) {
    void runMutation(async () => {
      const result = await previewDynamicGroup(group.dynamic_group_id);
      setPreview(result);
      setMessage(`Preview resolved ${result.matched_endpoint_count} authorized endpoints.`);
    });
  }

  const selectedEndpoint = endpoints.find(
    (endpoint) => endpoint.endpoint_id === selectedEndpointId,
  );

  return (
    <>
      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Fleet organization"
            title="Tags, views, and dynamic groups"
            description="Definitions remain inside the selected global, client, or location boundary. Group previews evaluate only endpoints the signed-in principal can read."
          />
          <div className="stat-grid">
            <StatCard label="Tags" value={tags.length} meta="Explicit endpoint labels" tone="info" />
            <StatCard label="Saved views" value={views.length} meta="Versioned allowlisted filters" tone="success" />
            <StatCard label="Dynamic groups" value={groups.length} meta="Live saved-view membership" tone="warning" />
          </div>
          <p className="panel__meta">Creation scope: {scopeLabel(resourceScope)}</p>
          {loading ? <p className="inline-feedback" role="status">Loading fleet metadata…</p> : null}
          {error ? <p className="inline-feedback inline-feedback--danger" role="status">Fleet metadata: {error}</p> : null}
          {message ? <p className="inline-feedback inline-feedback--success" role="status">{message}</p> : null}
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Tag assignment"
            title="Label an endpoint"
            description="Assignments are checked against both endpoint scope and tag scope before they are written."
          />
          <form className="form-grid" onSubmit={handleAssignTag}>
            <label className="field" htmlFor="metadata-endpoint">
              <span className="field__label">Endpoint</span>
              <select
                className="field__control"
                id="metadata-endpoint"
                onChange={(event) => setSelectedEndpointId(event.target.value)}
                value={selectedEndpointId}
              >
                <option value="">Select endpoint</option>
                {endpoints.map((endpoint) => (
                  <option key={endpoint.endpoint_id} value={endpoint.endpoint_id}>{endpoint.hostname}</option>
                ))}
              </select>
            </label>
            <label className="field" htmlFor="metadata-tag">
              <span className="field__label">Tag</span>
              <select
                className="field__control"
                id="metadata-tag"
                onChange={(event) => setSelectedTagId(event.target.value)}
                value={selectedTagId}
              >
                <option value="">Select tag</option>
                {tags.map((tag) => (
                  <option key={tag.tag_id} value={tag.tag_id}>{tag.name}</option>
                ))}
              </select>
            </label>
            <button
              className="action-button action-button--primary"
              disabled={pending || demoMode || !selectedEndpointId || !selectedTagId}
              type="submit"
            >
              Assign tag
            </button>
          </form>
          <div className="chip-list" aria-label="Assigned endpoint tags">
            {assignedTags.map((tag) => (
              <button
                className="chip"
                disabled={pending || demoMode}
                key={tag.tag_id}
                onClick={() => handleRemoveTag(tag)}
                type="button"
              >
                {tag.name} ×
              </button>
            ))}
          </div>
          {!assignedTags.length ? (
            <p className="panel__meta">{selectedEndpoint ? `${selectedEndpoint.hostname} has no tags.` : "Select an endpoint."}</p>
          ) : null}
        </Panel>
      </section>

      <section className="dashboard-grid dashboard-grid--wide-sidebar">
        <Panel>
          <SectionHeader
            eyebrow="Definitions"
            title="Create scoped metadata"
            description="Saved views accept a bounded declarative filter. This first UI slice exposes the platform predicate; the API contract also supports hostname, state, client, location, agent version, and tag predicates."
          />
          <form className="form-grid" onSubmit={handleCreateTag}>
            <label className="field" htmlFor="new-tag-name">
              <span className="field__label">New tag name</span>
              <input
                className="field__control"
                id="new-tag-name"
                maxLength={128}
                onChange={(event) => setTagName(event.target.value)}
                required
                value={tagName}
              />
            </label>
            <button className="action-button action-button--secondary" disabled={pending || demoMode} type="submit">
              Create tag
            </button>
          </form>

          <form className="form-grid" onSubmit={handleCreateView}>
            <label className="field" htmlFor="new-view-name">
              <span className="field__label">Saved view name</span>
              <input
                className="field__control"
                id="new-view-name"
                maxLength={128}
                onChange={(event) => setViewName(event.target.value)}
                required
                value={viewName}
              />
            </label>
            <label className="field" htmlFor="new-view-platform">
              <span className="field__label">Platform predicate</span>
              <select
                className="field__control"
                id="new-view-platform"
                onChange={(event) => setViewPlatform(event.target.value as Platform)}
                value={viewPlatform}
              >
                <option value="linux">Linux</option>
                <option value="windows">Windows</option>
                <option value="macos">macOS</option>
              </select>
            </label>
            <label className="field" htmlFor="new-view-visibility">
              <span className="field__label">Visibility</span>
              <select
                className="field__control"
                id="new-view-visibility"
                onChange={(event) => setViewVisibility(event.target.value as "private" | "shared")}
                value={viewVisibility}
              >
                <option value="shared">Shared in scope</option>
                <option value="private">Owner only</option>
              </select>
            </label>
            <button className="action-button action-button--secondary" disabled={pending || demoMode} type="submit">
              Save view
            </button>
          </form>

          <form className="form-grid" onSubmit={handleCreateGroup}>
            <label className="field" htmlFor="new-group-name">
              <span className="field__label">Dynamic group name</span>
              <input
                className="field__control"
                id="new-group-name"
                maxLength={128}
                onChange={(event) => setGroupName(event.target.value)}
                required
                value={groupName}
              />
            </label>
            <label className="field" htmlFor="new-group-view">
              <span className="field__label">Saved view</span>
              <select
                className="field__control"
                id="new-group-view"
                onChange={(event) => setGroupViewId(event.target.value)}
                value={groupViewId}
              >
                <option value="">Select saved view</option>
                {views.map((view) => (
                  <option key={view.saved_view_id} value={view.saved_view_id}>{view.name}</option>
                ))}
              </select>
            </label>
            <button
              className="action-button action-button--secondary"
              disabled={pending || demoMode || !groupViewId}
              type="submit"
            >
              Create dynamic group
            </button>
          </form>
        </Panel>

        <Panel>
          <SectionHeader
            eyebrow="Deterministic preview"
            title="Resolved group membership"
            description="Preview reports the exact saved-view version and filter hash used for the authorized evaluation."
          />
          {groups.length ? (
            <div className="stack-list">
              {groups.map((group) => (
                <div className="stack-list__item" key={group.dynamic_group_id}>
                  <div>
                    <strong>{group.name}</strong>
                    <p>{scopeLabel(group)} • view v{group.saved_view_version} • {group.filter_hash.slice(0, 12)}</p>
                  </div>
                  <button
                    className="action-button action-button--secondary"
                    disabled={pending}
                    onClick={() => handlePreview(group)}
                    type="button"
                  >
                    Preview {group.name}
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No dynamic groups" body="Create a saved view, then promote it into a targetable group." />
          )}
          {preview ? (
            <div className="table-card">
              <div className="table-card__header table-card__row">
                <span>Endpoint</span><span>Platform</span><span>Status</span><span>Scope</span><span>Version</span><span>Signal</span>
              </div>
              {preview.items.map((endpoint) => (
                <div className="table-card__row" key={endpoint.endpoint_id}>
                  <div><strong>{endpoint.hostname}</strong><p>{endpoint.endpoint_id}</p></div>
                  <span>{endpoint.platform}</span>
                  <Badge tone={endpoint.status === "active" ? "success" : "warning"}>{endpoint.status}</Badge>
                  <span>{endpoint.location_id}</span>
                  <span>v{preview.saved_view_version}</span>
                  <span>{endpoint.connectivity_status ?? "unknown"}</span>
                </div>
              ))}
              <p className="panel__meta">
                {preview.matched_endpoint_count} matched of {preview.evaluated_endpoint_count} authorized endpoints
                {preview.truncated ? `; showing first ${preview.result_limit}` : ""}.
              </p>
            </div>
          ) : null}
        </Panel>
      </section>

      <Panel>
        <SectionHeader
          eyebrow="Saved view catalog"
          title="Versioned fleet filters"
          description="Owner, visibility, scope, current version, and content digest remain visible before a view is used for targeting."
        />
        {views.length ? (
          <div className="table-card">
            <div className="table-card__header table-card__row">
              <span>View</span><span>Scope</span><span>Visibility</span><span>Owner</span><span>Version</span><span>Filter digest</span>
            </div>
            {views.map((view) => (
              <div className="table-card__row" key={view.saved_view_id}>
                <div><strong>{view.name}</strong><p>{view.saved_view_id}</p></div>
                <span>{scopeLabel(view)}</span>
                <Badge tone={view.visibility === "shared" ? "info" : "warning"}>{view.visibility}</Badge>
                <span>{view.owner_actor}</span>
                <span>v{view.current_version}</span>
                <span>{view.content_hash.slice(0, 12)}</span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState title="No saved views" body="Save a bounded fleet filter at the selected scope." />
        )}
      </Panel>
    </>
  );
}
