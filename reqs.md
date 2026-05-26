# "As-Data" on System Indices via ES|QL Views

[Brandon Kobel](mailto:brandon.kobel@elastic.co) Last update: May 20, 2026

## Background

The [implicit-privileges](https://docs.google.com/document/d/1aZSVsUV6oJDWvEN0g_sS3jiTQLpNHkvd7qbQZLzoayg/edit?tab=t.0#heading=h.y5qz35pe4e1o) work solves the *authorization* half of "as-data": Elasticsearch can automatically derive index-level privileges (including a DLS filter) from a user's Kibana application privileges, so a user with `feature_alerting_read` in the Marketing space can run `FROM .alerts-*` and only see Marketing alerts, without an administrator specifying index privileges directly using a. That model works well when the underlying index is a "hidden" index and is something we are comfortable exposing directly to end users, such as `.alerts-*`.

It does not work as well for anything that is stored in **system indices** — workflow executions, alerting rules, cases, connectors, dashboards, saved searches, ML job configs, etc.

This is for two reasons:x§

1) **System-index protections** prevent implicit access to system-indices underling an ES|QL view just like they would direct access  
2) **Lack of implicit FLS** The implicit privileges provider will need to be extended to specify FLS to hide especially sensitive fields

This one-pager is focused on system-index protections because the lack of implicit FLS has a well-known path forward.

## Goal

Allow a Kibana user, holding only the appropriate Kibana application privileges, to run an ES|QL query such as:

```
FROM workflows-executions
```

…where `workflows-executions` is a Kibana-managed ES|QL view backed by `FROM .workflows-executions`, with these properties:

1. The underlying index, `.workflows-executions`, is a system-index  
2. The user does not need (and is not granted) explicit `read` on `.workflows-executions`.  
3. The user's results are filtered by a DLS query derived from their Kibana application privileges (e.g., spaces, future per-object ACLs).  
4. The view, its DLS query, and its underlying index are all defined by Kibana — not by an administrator.

## Proposed Approach

### 1\. Kibana creates the view on startup

On startup, Kibana calls [`PUT /_query/view/{name}`](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-esql-put-view) for each resource type it wants to expose "as data". For example:

```
PUT /_query/view/workflows-executions
{
  "query": "FROM .workflows-executions | RENAME ... "
}
```

The view body is owned by Kibana and transforms the underlying data to be more human-readable. It does NOT protect sensitive data, implicit FLS will be used for this.

The `kibana_system` role will need to be granted the `create_view` index privilege required by the PUT view API.

### 2\. Implicit privileges grant view access \+ a DLS-filtered read on the system index

Utilizing the `ImplicitPrivilegesProvider`, the Kibana security plugin will register a provider that, for each relevant Kibana application privilege, emits **two** implicit index-privilege entries:

```json
{
  "indices": [
    {
      "names": ["workflows-executions"],
      "privileges": ["read"],
      "implicitly_granted": true
    },
    {
      "names": [".workflows-executions"],
      "privileges": ["read"],
      "query": "{\"terms\": {\"space_id\": [\"marketing\"]}}",
      "implicitly_granted": true,
      "allow_restricted_indices": true
    }
  ]
}
```

The first entry lets the user invoke the view. The second entry is the existing implicit-privileges pattern, with two important wrinkles for system indices:

- The DLS query is derived from the user's Kibana role (spaces today; per-object ACLs later) and benefits from the same basic-license bypass the alerts work already established for implicit DLS.  
- `allow_restricted_indices` is set so the implicit grant can target a system index. This is normally reserved for operator-level roles, so it must only be settable by an `ImplicitPrivilegesProvider`, never by an administrator-defined role.

### 3\. The system-index restriction is bypassed only when the access comes through the view

This is the piece that needs explicit support from the unknown ES teams.

ES|QL's invoker-model views today execute "transparently" — the caller's privileges are checked against the underlying indices just as if they had typed the view's body themselves. For the as-data case, we want a narrower exception, not a switch to definer-model:

When an implicit privilege grants `read` on a system index *and* `read` on a view whose body resolves to that system index, querying the view succeeds even though directly querying the system index by name does not.

In practice this means:

- A direct `FROM .workflows-executions` from a normal user is rejected by the system-index gate, even though the user technically has the implicit DLS-filtered read grant. The system-index gate is enforced on the *request*'s index expression, not just on the role.  
- `FROM workflows-executions` (the view) is allowed. When ES|QL resolves the view to its underlying `FROM .workflows-executions`, the system-index check is satisfied because (a) the resolution came from a Kibana-managed view rather than from the user's query, and (b) the user has the implicit DLS-filtered grant.

Concretely, we need one of:

1. A view-level marker (set only by privileged callers such as Kibana) that opts the view's underlying indices into the same `allow_restricted_indices` treatment that the implicit privilege uses, scoped to that view's resolution only.  
2. Treating the act of resolving a view as equivalent to `allow_restricted_indices: true` for the duration of that resolution, with the user's normal role still applied (so they only see what the implicit DLS lets them see).

### 4\. Why this is acceptable from a security standpoint

- **No new privilege escalation surface.** The view body, the implicit DLS query, and the `allow_restricted_indices` exemption are all authored by Kibana code running in Elasticsearch, not by tenant administrators. This is the same trust boundary that `ImplicitPrivilegesProvider` already establishes.  
- **No leaking of cross-tenant rows.** The implicit DLS query is the same mechanism that already gates `.alerts-*` access by space, including the basic-license bypass for implicit DLS.  
- **No "definer model" semantics.** We are not asking ES|QL to execute the view under a different identity, and we are not asking for arbitrary DSL fragments to be evaluated outside the caller's permission context. The caller's role is still the source of truth; we just want one specific role (the implicitly-granted one) to be allowed to read a system index when the access is funnelled through a Kibana-managed view.

