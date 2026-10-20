-- SYNTHETIC PostgreSQL deployment variant; not run and not the SQLite demo DB.
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_owner ON notes
  USING (tenant_id = current_setting('atlas.tenant_id') AND owner_id = current_setting('atlas.actor_id'))
  WITH CHECK (tenant_id = current_setting('atlas.tenant_id') AND owner_id = current_setting('atlas.actor_id'));
-- The trusted service sets transaction-local settings from an authenticated principal.
-- App connection role is NOSUPERUSER NOBYPASSRLS, never the table owner.
-- Parameterized SQL and per-request connection reset remain required.
