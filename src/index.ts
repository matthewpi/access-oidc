//
// Copyright (c) 2022 Matthew Penner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

import type { JWTPayload, JWTVerifyResult } from './jose';
import { API } from './cloudflare';
import {
	durableObjectStorageProvider,
	getAuthRequestQuery,
	getClientRegistrationBody,
	getClientResponse,
	getConfiguration,
	getTokenRequestBody,
	parseTokenAuthorization,
	verifyChallenge,
} from './oidc-provider';
import type {
	AuthorizationError,
	AuthRequestQuery,
	AuthorizationCode,
	Client,
	TokenAuthMethod,
} from './oidc-provider';
import { JsonResponse, Router } from './router';
import type { RouterRequest } from './router';
import type { Env } from './types';

function getIssuer(request: Request): string {
	const url = new URL(request.url);

	if (
		// eslint-disable-next-line node/prefer-global/process
		process.env.NODE_ENV === 'development' &&
		(url.hostname === '127.0.0.1' || url.hostname === 'localhost')
	) {
		return `${url.protocol}//${url.hostname}${url.port === '' ? '' : ':' + url.port}`;
	}

	return `https://${url.hostname}`;
}

function getCustomUserinfo(custom: Record<string, unknown> | undefined): Record<string, unknown> {
	const payload: Record<string, string | string[]> = {};

	if (custom === undefined) {
		return payload;
	}

	if (custom.preferred_username !== undefined && typeof custom.preferred_username === 'string') {
		payload.preferred_username = custom.preferred_username;
	}

	if (custom.groups !== undefined) {
		let groups: string[] | undefined;
		if (typeof custom.groups === 'string') {
			groups = [custom.groups];
		} else if (Array.isArray(custom.groups)) {
			groups = custom.groups;
		}

		if (groups !== undefined) {
			payload.groups = groups;
		}
	}

	if (custom.givenName !== undefined && typeof custom.givenName === 'string') {
		payload.given_name = custom.givenName;
	}

	if (custom.surname !== undefined && typeof custom.surname === 'string') {
		payload.family_name = custom.surname;
	}

	if (
		payload.given_name !== undefined &&
		typeof payload.given_name === 'string' &&
		payload.family_name !== undefined &&
		typeof payload.family_name === 'string'
	) {
		payload.name = `${payload.given_name} ${payload.family_name}`;
	}

	return payload;
}

const router = new Router();

router.get('/.well-known/openid-configuration', request => {
	return JsonResponse(JSON.stringify(getConfiguration(getIssuer(request)), null, '\t'));
});

router.get('/protocol/openid-connect/auth', async (request, env: Env) => {
	const query: AuthRequestQuery | AuthorizationError = await getAuthRequestQuery(
		request.query,
		env,
	);

	if ('error' in query) {
		const response = query;
		if (response.redirectUri !== undefined) {
			const redirectUrlSearchParameters = new URLSearchParams();
			redirectUrlSearchParameters.set('error', response.error);

			if (response.error_description !== undefined) {
				redirectUrlSearchParameters.set('error_description', response.error_description);
			}

			if (response.error_uri !== undefined) {
				redirectUrlSearchParameters.set('error_uri', response.error_uri);
			}

			if (response.state !== undefined) {
				redirectUrlSearchParameters.set('state', response.state);
			}

			return Response.redirect(
				`${response.redirectUri}?${redirectUrlSearchParameters.toString()}`,
			);
		}

		response.state = undefined;

		return JsonResponse(response, {
			status: 400,
		});
	}

	const accessToken = request.headers.get('Cf-Access-JWT-Assertion');
	if (accessToken === null) {
		console.error('application is not behind Access or Access is not sending a token');
		return JsonResponse(
			{ error: 'server_error' },
			{
				status: 500,
			},
		);
	}

	const api = new API(env);
	let result: JWTVerifyResult;
	try {
		result = await api.verifyCloudflareAccessJWT(accessToken);
	} catch {
		return JsonResponse(
			{ error: 'invalid_token', error_description: 'invalid token provided' },
			{
				status: 401,
				headers: {
					'WWW-Authenticate':
						'Bearer error="invalid_token" error_description="invalid token provided"',
				},
			},
		);
	}

	const createdAt = new Date();
	const expiresAt = new Date();
	expiresAt.setMinutes(expiresAt.getMinutes() + 3);

	const authorizationCode: Omit<AuthorizationCode, 'tokens'> = {
		code: crypto.randomUUID(),
		clientId: query.clientId,
		redirectUri: query.redirectUri,
		scope: query.scopes.join(' '),
		codeChallenge: query.codeChallenge,
		createdAt,
		expiresAt,
	};

	// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	const payload: JWTPayload = {
		...getCustomUserinfo(
			'custom' in result.payload ? (result.payload.custom as Record<string, any>) : undefined,
		),
		iss: getIssuer(request),
		aud: query.clientId,
		azp: query.clientId,
		sub: result.payload.sub,
		email: result.payload.email,
		country: result.payload.country,
		// https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
		nonce: query.nonce,
		auth_time: result.payload.iat,
	};

	const response = await durableObjectStorageProvider.persistAuthorizationCode(env, {
		accessToken,
		code: authorizationCode,
		payload,
		responseType: query.responseType,
		exp: result.payload.exp ?? 0,
	});
	if (response instanceof Response) {
		return response;
	}

	const redirectSearchParameters = new URLSearchParams();
	if (query.responseType.includes('code')) {
		redirectSearchParameters.set('code', response.code);
	}

	if (query.responseType.endsWith(' token')) {
		redirectSearchParameters.set('access_token', response.tokens.accessToken);
		redirectSearchParameters.set(
			'expires_in',
			Math.ceil(response.tokens.exp - Date.now() / 1000).toString(),
		);
		redirectSearchParameters.set('scope', response.scope);
	}

	if (query.responseType.includes('id_token')) {
		redirectSearchParameters.set('id_token', response.tokens.idToken);
	}

	if (query.state !== undefined) {
		redirectSearchParameters.set('state', query.state);
	}

	if (query.nonce !== undefined) {
		redirectSearchParameters.set('nonce', query.nonce);
	}

	return Response.redirect(`${query.redirectUri}?${redirectSearchParameters.toString()}`);
});

router.post('/protocol/openid-connect/token', async (request, env: Env) => {
	const formData = await request.formData();

	let tokenAuthMethod: TokenAuthMethod = 'client_secret_post';
	// TODO: support client_secret_jwt, private_key_jwt, and none.
	const body = getTokenRequestBody(formData);
	if ('error' in body) {
		return JsonResponse(body, {
			status: 400,
		});
	}

	const authorizationHeader = request.headers.get('Authorization');
	if (authorizationHeader !== null) {
		const authorization = parseTokenAuthorization(authorizationHeader);
		if ('error' in authorization) {
			return JsonResponse(authorization, {
				status: 400,
			});
		}

		body.clientId = authorization.clientId;
		body.clientSecret = authorization.clientSecret;
		tokenAuthMethod = 'client_secret_basic';
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	const invalidClientResponse = JsonResponse(
		{
			error: 'invalid_client',
		},
		{
			status: 401,
			headers:
				authorizationHeader === null
					? undefined
					: {
							'WWW-Authenticate': 'Basic',
					  },
		},
	);

	if (body.clientId === undefined || body.clientSecret === undefined) {
		return invalidClientResponse;
	}

	const client = await env.KV_OIDC.get<Client>('clients:' + body.clientId, 'json');
	if (client === null) {
		return invalidClientResponse;
	}

	if (client.tokenEndpointAuthMethod !== tokenAuthMethod) {
		// TODO: is there another way to handle this?
		return invalidClientResponse;
	}

	// TODO: Use bcrypt or argon2
	if (body.clientSecret !== client.clientSecret) {
		return invalidClientResponse;
	}

	const { clientId, code, redirectUri, codeVerifier } = body;

	const response = await durableObjectStorageProvider.exchangeAuthorizationCode(env, code);
	if (response instanceof Response) {
		return response;
	}

	const authorizationCode = response;

	if (authorizationCode.clientId !== clientId) {
		return JsonResponse(
			{ error: 'invalid_request', error_description: 'authentication failed' },
			{
				status: 401,
			},
		);
	}

	if (authorizationCode.redirectUri !== redirectUri) {
		return JsonResponse(
			{ error: 'invalid_request', error_description: 'authentication failed' },
			{
				status: 401,
			},
		);
	}

	// Check if the authorize request had a PKCE challenge.
	if (authorizationCode.codeChallenge !== undefined) {
		// Check if the client didn't send a PKCE verifier.
		if (codeVerifier === undefined) {
			return JsonResponse(
				{ error: 'invalid_request', error_description: 'authentication failed' },
				{
					status: 401,
				},
			);
		}

		// Verify the challenge.
		const verified = await verifyChallenge(
			authorizationCode.codeChallenge.method,
			authorizationCode.codeChallenge.challenge,
			codeVerifier,
		);
		if (!verified) {
			// https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
			// If the values are not equal, an error response indicating "invalid_grant" as described
			// in Section 5.2 of [RFC6749] MUST be returned.
			return JsonResponse(
				{ error: 'invalid_grant' },
				{
					status: 400,
				},
			);
		}
	}

	return JsonResponse({
		access_token: authorizationCode.tokens.accessToken,
		token_type: 'Bearer',
		expires_in: Math.ceil(authorizationCode.tokens.exp - Date.now() / 1000),
		scope: authorizationCode.scope,
		id_token: authorizationCode.tokens.idToken,
	});
});

async function getUserinfo(request: RouterRequest, env: Env): Promise<Response> {
	// https://datatracker.ietf.org/doc/html/rfc6750#section-3
	const authorization = request.headers.get('Authorization');
	if (authorization === null || !authorization.startsWith('Bearer ')) {
		// https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
		return JsonResponse(
			{
				error: 'invalid_request',
				error_description: 'missing required header(s) Authorization',
			},
			{
				status: 401,
				headers: {
					'WWW-Authenticate': 'Bearer',
				},
			},
		);
	}

	const accessToken = authorization.slice('Bearer '.length);

	const identity = await new API(env).getCloudflareAccessIdentity(accessToken);
	if ('err' in identity) {
		// https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
		return JsonResponse(
			{ error: 'invalid_token', error_description: 'invalid token provided' },
			{
				status: 401,
				headers: {
					'WWW-Authenticate':
						'Bearer error="invalid_token" error_description="invalid token provided"',
				},
			},
		);
	}

	const payload: Record<string, any> = {
		...getCustomUserinfo(identity.custom),
		sub: identity.user_uuid,
		name: identity.name,
		given_name: identity.givenName,
		family_name: identity.surName,
		email: identity.email,
	};

	return JsonResponse(payload);
}

router.get('/protocol/openid-connect/userinfo', getUserinfo);
router.post('/protocol/openid-connect/userinfo', getUserinfo);

router.get('/protocol/openid-connect/certs', async (_, env: Env) => {
	const response = await durableObjectStorageProvider.getJWKs(env);
	if (response instanceof Response) {
		return response;
	}

	return JsonResponse(JSON.stringify({ keys: response }, null, '\t'));
});

router.post('/protocol/openid-connect/token/introspect', () => {
	return new Response(null);
});

router.post('/protocol/openid-connect/token/revoke', () => {
	return new Response(null);
});

async function bearerAuthentication(request: RouterRequest, env: Env): Promise<Response | void> {
	// https://datatracker.ietf.org/doc/html/rfc6750#section-3
	const authorization = request.headers.get('Authorization');
	if (authorization === null || !authorization.startsWith('Bearer ')) {
		// https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
		return JsonResponse(
			{
				error: 'invalid_request',
				error_description: 'missing required header(s) Authorization',
			},
			{
				status: 401,
				headers: {
					'WWW-Authenticate': 'Bearer',
				},
			},
		);
	}

	const accessToken = authorization.slice('Bearer '.length);

	const api = new API(env);
	let result: JWTVerifyResult;
	try {
		result = await api.verifyCloudflareAccessJWT(accessToken);
	} catch {
		return JsonResponse(
			{ error: 'invalid_token', error_description: 'invalid token provided' },
			{
				status: 401,
				headers: {
					'WWW-Authenticate':
						'Bearer error="invalid_token" error_description="invalid token provided"',
				},
			},
		);
	}

	let authorized = false;
	if ('custom' in result.payload) {
		const custom = result.payload.custom as Record<string, unknown>;

		let groups: string[] = [];
		if (custom.groups !== undefined) {
			if (typeof custom.groups === 'string') {
				groups = [custom.groups];
			} else if (Array.isArray(custom.groups)) {
				groups = custom.groups as string[];
			}
		}

		authorized = groups.includes('admin');
	}

	if (!authorized) {
		return JsonResponse(
			{ error: 'access_denied', error_description: 'no permission' },
			{
				status: 403,
				headers: {
					'WWW-Authenticate':
						'Bearer error="access_denied" error_description="no permission"',
				},
			},
		);
	}
}

router.get('/client-registrations/openid-connect', bearerAuthentication, async (_, env: Env) => {
	const list = await env.KV_OIDC.list({
		prefix: 'clients:',
	});

	const clientKeys = list.keys.map(c => c.name);
	const clients: Client[] = [];
	for (const key of clientKeys) {
		// eslint-disable-next-line no-await-in-loop
		const client = await env.KV_OIDC.get<Client>(key, 'json');
		if (client === null) {
			continue;
		}

		client.clientIdIssuedAt = new Date(client.clientIdIssuedAt);
		client.clientSecretExpiresAt =
			client.clientSecretExpiresAt === undefined
				? undefined
				: new Date(client.clientSecretExpiresAt);
		client.clientSecret = undefined;
		clients.push(client);
	}

	return JsonResponse(clients.map(c => getClientResponse(c)));
});

router.post(
	'/client-registrations/openid-connect',
	bearerAuthentication,
	async (request, env: Env) => {
		const body = await request.json<Record<string, any>>();

		const clientMetadata = getClientRegistrationBody(body);
		if ('error' in clientMetadata) {
			return JsonResponse(clientMetadata, { status: 400 });
		}

		const client: Client = {
			...clientMetadata,
			clientId: crypto.randomUUID(),
			clientIdIssuedAt: new Date(),
			clientSecret: crypto.randomUUID(),
		};

		await env.KV_OIDC.put('clients:' + client.clientId, JSON.stringify(client));

		return JsonResponse(getClientResponse(client));
	},
);

router.get(
	'/client-registrations/openid-connect/:clientId',
	bearerAuthentication,
	async (request, env: Env) => {
		if (request.params === undefined) {
			return JsonResponse();
		}

		const client = await env.KV_OIDC.get<Client>('clients:' + request.params.clientId, 'json');
		if (client === null) {
			return JsonResponse(
				{ error: 'invalid_client', error_description: 'resource not found' },
				{ status: 404 },
			);
		}

		client.clientIdIssuedAt = new Date(client.clientIdIssuedAt);
		client.clientSecretExpiresAt =
			client.clientSecretExpiresAt === undefined
				? undefined
				: new Date(client.clientSecretExpiresAt);
		client.clientSecret = undefined;
		return JsonResponse(getClientResponse(client));
	},
);

router.patch('/client-registrations/openid-connect/:clientId', bearerAuthentication, request => {
	if (request.params === undefined) {
		return JsonResponse();
	}

	// TODO: implement

	return JsonResponse();
});

router.delete(
	'/client-registrations/openid-connect/:clientId',
	bearerAuthentication,
	async (request, env: Env) => {
		if (request.params === undefined) {
			return JsonResponse();
		}

		await env.KV_OIDC.delete('clients:' + request.params.clientId);

		return new Response(null, { status: 204 });
	},
);

router.all('*', () => new Response(null, { status: 404 }));

// eslint-disable-next-line import/no-anonymous-default-export
export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		try {
			return await router.handle(request, env);
		} catch (error: unknown) {
			if (error instanceof Error) {
				console.error(error);
			}

			return JsonResponse({ error: 'server_error' }, { status: 500 });
		}
	},

	// Cron task cleans up expired JWKS.
	async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
		try {
			ctx.waitUntil(durableObjectStorageProvider.cleanupJWKs(env));
		} catch (error: unknown) {
			console.error(error);
		}
	},
};

export { OpenIDConnectDurableObject } from './oidc-provider/storage/durable-object';
