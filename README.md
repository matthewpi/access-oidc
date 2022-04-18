# Access OIDC

OpenID Connect server running on Cloudflare Workers and authenticated by Cloudflare Zero Trust.

Inspired by [eidam](https://github.com/eidam)'s [OIDC worker](https://github.com/eidam/cf-access-workers-oidc).

## About

This worker can be used to enable you to sign in to applications that do not support forward-proxy
or SAML authentication (for SaaS applications) which Cloudflare Zero Trust is designed to be used
with. Examples of applications that don't work easily with Cloudflare Access are:

- [HashiCorp Vault](https://vaultproject.io)
  - Does not support forward-proxy authentication.
- [Kubernetes](https://kubernetes.io)
  - Yes, you can use this worker to authenticate against a Kubernetes cluster regardless of if
    your cluster is protected by Cloudflare Zero Trust.

There are many more applications that support OpenID Connect, but these are some of the applications
I use that don't support forward-proxy authentication (or support it easily).

## Usage

### Prerequisites

- [Cloudflare Account](https://dash.cloudflare.com/sign-up)
- [Workers Paid Plan](https://dash.cloudflare.com/?to=/:account/workers/plans)
- [Wrangler](https://developers.cloudflare.com/workers/get-started/guide#1-sign-up-for-a-workers-account)
  - The rest of these steps assume you are authenticated with the `wrangler` CLI and can deploy workers.

This project uses [Durable Objects](https://developers.cloudflare.com/workers/learning/using-durable-objects)
which requires the [Workers Paid](https://developers.cloudflare.com/workers/platform/pricing) plan. See
[Durable Objects Pricing](https://developers.cloudflare.com/workers/platform/pricing#durable-objects) for more
information.

This worker will not work properly if you deploy the worker with only a `workers.dev` domain, the
`/protocol/openid-connect/auth` endpoint needs to be protected
by [Cloudflare Zero Trust](https://developers.cloudflare.com/cloudflare-one/) which can
only be done with a custom domain.

### First-time Setup

If this is the first time you are deploying the Worker, you will need to run the following steps in
order to deploy the worker.

You will first need to create a Cloudflare Zero Trust application using
the [Cloudflare Zero Trust Dashboard](https://dash.teams.cloudflare.com).

#### Create a [Cloudflare Zero Trust Application](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/self-hosted-apps)

1. Application type `Self-hosted`
2. Application name, whatever you want. I used `OpenID Connect Identity Provider`.
3. Session duration, whatever you want. I used `30 minutes`.
4. Application domain, pick a domain and optionally specify a subdomain (for example `oidc.example.com`).
   For the path, use `/protocol/openid-connect/auth`
5. Click `Next` and configure whatever polices you want.
6. Click `Next` and leave the CORS Settings empty
7. Under `Cookie settings`
   1. Set `Same Site Attribute` to `Lax`
   2. Enable `HTTP Only`
   3. Keep `Enable Binding Cookie` disabled
   4. Enabling this setting will cause a redirect loop when using the `auth` endpoint.
8. Click `Add application`
9. Edit the application, select `Overview`.
10. Copy the `Application Audience (AUD) Tag` value.

#### Wrangler Configuration

Copy the `wrangler.example.toml`:

```sh
cp wrangler.example.toml wrangler.toml
```

Open the `wrangler.toml` you just copied in an editor of your choice.

1. From the step section where you created a zero-trust application, copy the `Application Audience (AUD) Tag` and
   update the value of the `SECRET_CF_ACCESS_AUD` variable.
2. `<ACCOUNT_ID>` and `<ZONE_ID>`, click this [link](https://dash.cloudflare.com/?to=/:account/:zone),
   select the target account and domain, then scroll down on the page until you see the `API`
   section on the left side of the page.
   1. Make sure the zone (domain) you select is the same one you used when creating the Cloudflare Zero Trust application.
   2. This link is a magic link for the Cloudflare Dashboard which will force you to select an account
      and domain, so you can get your `Account ID` and `Zone ID` easier, you can avoid using this link
      if you log in to the Cloudflare dashboard and select a domain from one of your accounts.
3. `<DOMAIN>` should be the same domain (including the subdomain) you configured when creating the Cloudflare Zero
   Trust application.
4. Set the value of the `SECRET_CF_ACCESS_TEAM` variable to your
   Access [Team Name](https://developers.cloudflare.com/cloudflare-one/glossary#team-name)

Create a KV namespace:

```sh
wrangler kv:namespace create "KV_OIDC"
```

_Once created, add it to the `wrangler.toml` under the `kv_namespaces` field._

#### Deploying

Deploy the worker:

```sh
wrangler publish
```

### Development

Install dependencies:

```sh
yarn install --immutable
```

Start the [`miniflare`](https://github.com/cloudflare/miniflare) development server:

```sh
yarn run dev
```

## References

- The OAuth 2.0 Authorization Framework [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
  - Implemented Partially
  - Response Types
    - Authorization Code `code` - Implemented
    - Implicit `token` - Unsupported
      - "NOTE: While OAuth 2.0 also defines the `token` Response Type value for the Implicit Flow, OpenID Connect does
        not use this Response Type, since no ID Token would be
        returned." [ref](https://openid.net/specs/openid-connect-core-1_0.html#Authentication)
      - Use the `id_token` or `id_token token` Response Types from the `OpenID Connect Core` spec instead
  - Grant Types
    - Authorization Code `authorization_code` - Implemented
    - Access Token `client_credentials` - Unimplemented
    - Refresh Token `refresh_token` - Unimplemented
- The OAuth 2.0 Authorization Framework: Bearer Token Usage [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)
  - Implemented
- _OAuth 2.0 Token Revocation [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)_
  - Soon&trade;
- Proof Key for Code Exchange by OAuth Public Clients [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
  - Implemented
- _OAuth 2.0 Token Introspection [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)_
  - Soon&trade;
- _OAuth 2.0 for Native Apps [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252)_
  - Soon&trade;
- _OAuth 2.0 Authorization Server Metadata [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)_
  - Soon&trade;
- _OAuth 2.0 Device Authorization Grant [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)_
  - Soon&trade;
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
  - Implemented Partially
  - Response Types
    - Authorization Code `code` - Implemented
    - Implicit `id_token`, `id_token token` - Implemented (untested)
    - Hybrid `code id_token`, `code token`, `code id_token token` - Implemented (untested)
  - Grant Types
    - Authorization Code `authorization_code` - Implemented
    - Refresh Token `refresh_token` - Unimplemented
      - See <https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess> for details
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
  - Implemented
- [OpenID Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html)
  - Implemented Partially

### Security Considerations

- OAuth 2.0 Threat Model and Security Considerations [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819)
- OAuth 2.0 Security Best Current
  Practice [draft-ietf-oauth-security-topics](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

### Notable Mentions

- OAuth 2.0 for Browser-Based
  Apps [draft-ietf-oauth-browser-based-apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (
  JAR) [RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101)
- OAuth 2.0 Pushed Authorization Requests [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126)
- OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access
  Tokens [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)
- [OAuth 2.0 Multiple Response Types](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
