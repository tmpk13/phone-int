# phone-int

The relay for cld-phone: a Rust Cloudflare Worker that carries Claude's
questions to a phone and the answers (text, files, photos) back. Messages are
kept in D1, files in R2.

This repo is exported from cld-phone (`mise run export` there); change the
code in cld-phone and export again rather than editing here.

## Deploy from GitHub

1. Cloudflare dashboard: Workers & Pages > Create > Import a repository >
   `phone-int`. Name the Worker `cld-phone`; it has to match `name` in
   `wrangler.toml`.
2. Build settings:
   - Build command: `sh build.sh`
   - Deploy command: `npx wrangler deploy` (the default)
   - Root directory: `/`

   Workers Builds does not run the `[build]` step of `wrangler.toml`, so the
   build command has to be set here. Each build installs Rust and
   `worker-build` first and takes several minutes.
3. R2 has to be enabled on the account (dashboard > R2). The first deploy
   creates the D1 database and the R2 bucket; later deploys keep them. The
   worker creates its own tables.
4. On the host: `cldp setup https://cld-phone.<subdomain>.workers.dev`, then
   `cldp secrets` prints the two values for the next step.
5. Worker > Settings > Variables and Secrets, type **Secret**:
   - `HOST_TOKEN` and `TOTP_SECRET` from `cldp secrets`
   - optional `NTFY_URL` (an ntfy topic URL) and `NTFY_TOKEN` for push
     notifications

   Optional plain variables:
   - `NTFY_PREVIEW` = `1` puts the message text in notifications.
   - `STORAGE_LIMIT_MB` (default 2048), `UPLOADS_PER_DAY` (default 1000) and
     `DOWNLOADS_PER_DAY` (default 10000) cap R2 use. The defaults keep a
     month under 2 GB stored, 31,000 writes and 310,000 reads, against the
     free tier's 10 GB, 1 million and 10 million (shared by all buckets on
     the account). Past a cap the relay answers 507 or 429; `cldp status`
     shows the counts.
6. `cldp status` should list the relay and "no phone paired".

Until the secrets are set, the worker answers 401 to the host and 503 to
pairing.

## Files

| Path | What |
| --- | --- |
| `worker/` | the Worker (workers-rs) and `schema.sql` |
| `proto/` | wire types, TOTP and pairing rules shared with the CLI and app |
| `build.sh` | the build command |
| `wrangler.toml` | bindings and the daily cleanup |

Quick local build check: `CLD_PHONE_BUILD=--dev sh build.sh`.
