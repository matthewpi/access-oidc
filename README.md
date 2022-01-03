# Access OIDC

OpenID Connect server running on Cloudflare Workers and authenticated by Cloudflare Access.

## Usage

### Prerequisites

- [Cloudflare Account](https://dash.cloudflare.com/sign-up)
- [Workers Paid Plan](https://dash.cloudflare.com/?to=/:account/workers/plans)
- [Wrangler](https://developers.cloudflare.com/workers/get-started/guide#1-sign-up-for-a-workers-account)
  - The rest of these steps assume you are authenticated with the `wrangler` CLI and can deploy workers.

### First-time Setup

If this is the first time you are deploying the Worker, you will need to run the following commands
in order to setup the wrangler configuration.

Copy the `wrangler.example.toml`:
```sh
cp wrangler.example.toml wrangler.toml
```

Open the `wrangler.toml` you just copied in an editor of your choice, replace:

1. `<ACCOUNT_ID>` and `<ZONE_ID>`, click this [link](https://dash.cloudflare.com/?to=/:account/:zone)
   and select the target account and domain, then scroll down on the page until you see the `API`
   section on the left side of the page.
   1. This link is a magic link for Cloudflare's Dashboard which will force you to select and account
      and domain so you can find your `Account ID` and `Zone ID` easier, you can avoid using that link
      if you login to the dashboard and select a domain from one of your accounts.
2. `<DOMAIN>`, this should be the same domain you selected in the previous step or a subdomain of it.
   1. So if you selected `example.com` in the step above, you must use `example.com` OR `*.example.com`
3. Set the value of the `SECRET_CF_ACCESS_TEAM` variable to your Access [Team Name](https://developers.cloudflare.com/cloudflare-one/glossary#team-name)
4. Create an [Application](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/self-hosted-apps)
   1. Application type `Self-hosted`
   2. Application name, whatever you want.  I used `OpenID Connect Identity Provider`.
   3. Session duration, whatever you want.  I used `30 minutes`.
   4. Application domain, use `<DOMAIN>` from the previous step.  For the path, use `/protocol/openid-connect/auth`
   5. Click `Next` and configure whatever polices you want.
   6. Click `Next`, leave the CORS Settings empty
      1. Set `Same Site Attribute` to `Strict`
      2. Enable `HTTP Only`
      3. Keep `Enable Binding Cookie` disabled
         1. Enabling this setting will cause a redirect loop when using the `auth` endpoint.
   7. Click `Add application`
   8. Edit the application, select `Overview`.
   9. Copy `Application Audience (AUD) Tag` and update the value of the `SECRET_CF_ACCESS_AUD` variable.

Create a KV namespace:
```sh
wrangler kv:namespace create "KV_OIDC"
```
*Once created, add it to the `wrangler.toml` under the `kv_namespaces` field.*

### Development

Install dependencies:
```sh
yarn install --immutable
```

Start the [`miniflare`](https://github.com/cloudflare/miniflare) development server:
```sh
yarn run dev
```

### Production

This project uses [Durable Objects](https://developers.cloudflare.com/workers/learning/using-durable-objects)
which requires the [Workers Paid](https://developers.cloudflare.com/workers/platform/pricing) plan.  See
[Durable Objects Pricing](https://developers.cloudflare.com/workers/platform/pricing#durable-objects) for more information.

This worker will not work properly if you deploy the worker with only a `workers.dev` domain, the
`/protocol/openid-connect/auth` endpoint needs to be protected by [Cloudflare Access](#) which can
only be done with a custom domain.

Install dependencies:
```sh
yarn install --immutable
```

Deploy the worker:
```sh
wrangler publish
```

## References

- The OAuth 2.0 Authorization Framework [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
  - Implemented Partially
  - Response Types
    - Authorization Code `code` - Implemented
    - Implicit `token` - Unsupported
      - "NOTE: While OAuth 2.0 also defines the `token` Response Type value for the Implicit Flow, OpenID Connect does not use this Response Type, since no ID Token would be returned." [ref](https://openid.net/specs/openid-connect-core-1_0.html#Authentication)
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
- OAuth 2.0 Security Best Current Practice [draft-ietf-oauth-security-topics](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

### Notable Mentions

- OAuth 2.0 for Browser-Based Apps [draft-ietf-oauth-browser-based-apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR) [RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101)
- OAuth 2.0 Pushed Authorization Requests [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126)
- OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)
- [OAuth 2.0 Multiple Response Types](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
