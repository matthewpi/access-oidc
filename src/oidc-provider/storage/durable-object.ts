//
// Copyright (c) 2021 Matthew Penner
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

import { SignJWT } from 'jose';

import type { JWK, JWTHeaderParameters, KeyLike } from '../../jose';
import { exportJWK, generateKeyPair } from '../../jose';
import type { Curve } from '../../oidc-token-hash';
import { generate } from '../../oidc-token-hash';
import type { RouterRequest } from '../../router';
import { JsonResponse, Router } from '../../router';
import type { Env } from '../../types';
import type { AuthorizationCode } from '../authorization-code';
import type { SigningAlgorithm } from '../discovery';
import type { PersistAuthorizationCode, StorageProvider } from './index';

interface PrivateKey {
	id: string;
	key: KeyLike;
}

interface SigningJWK {
	lastSignature: Date;
	jwk: JWK;
}

function getDurableObjectStub(env: Env): DurableObjectStub {
	const oidcDoId = env.DO_OIDC.idFromName('oidc');

	return env.DO_OIDC.get(oidcDoId);
}

export const durableObjectStorageProvider: StorageProvider = {
	async exchangeAuthorizationCode(env: Env, code: string): Promise<AuthorizationCode | Response> {
		const stub = getDurableObjectStub(env);
		const response = await stub.fetch('https://.../exchangeAuthorizationCode', {
			method: 'POST',
			body: JSON.stringify({
				code,
			}),
			headers: {
				'Content-Type': 'application/json; charset=utf-8',
			},
		});
		if (response.status !== 200) {
			return response;
		}

		return response.json<AuthorizationCode>();
	},

	async persistAuthorizationCode(
		env: Env,
		request: PersistAuthorizationCode,
	): Promise<AuthorizationCode | Response> {
		const stub = getDurableObjectStub(env);
		const response = await stub.fetch('https://.../persistAuthorizationCode', {
			method: 'POST',
			body: JSON.stringify(request),
			headers: {
				'Content-Type': 'application/json; charset=utf-8',
			},
		});
		if (response.status !== 200) {
			return response;
		}

		return response.json<AuthorizationCode>();
	},

	async getJWKs(env: Env): Promise<JWK[] | Response> {
		const stub = getDurableObjectStub(env);
		const response = await stub.fetch('https://.../jwks');
		if (response.status !== 200) {
			return response;
		}

		return response.json<JWK[]>();
	},

	async cleanupJWKs(env: Env): Promise<Response | undefined> {
		const stub = getDurableObjectStub(env);
		const response = await stub.fetch('https://.../jwks', { method: 'PATCH' });
		if (response.status !== 204) {
			return response;
		}

		return undefined;
	},
};

/**
 * This storage back-end is a special little butterfly.
 *
 * Anything stored outside `storage` will only be persisted for a short period of time,
 * "a Durable Object may be evicted from memory any time, causing a loss of all transient (in-
 * memory) state."
 *
 * This backend only persistently stores the public keys used for verifying the signed JWTs,
 * private keys and authorization codes are only temporarily persisted before being yeeted
 * into the void whenever the DO decides to die.
 *
 * Inspired by https://github.com/eidam/cf-access-workers-oidc
 */
export class OpenIDConnectDurableObject {
	private readonly state: DurableObjectState;
	private readonly storage: DurableObjectStorage;

	private authorizationCodes!: Map<string, AuthorizationCode>;
	private jwks!: Map<string, SigningJWK>;
	private privateKey?: PrivateKey;

	private router!: Router;

	constructor(state: DurableObjectState) {
		this.state = state;
		this.storage = state.storage;

		// eslint-disable-next-line @typescript-eslint/no-floating-promises
		this.state.blockConcurrencyWhile(async () => {
			this.authorizationCodes = new Map();
			this.jwks = await this.storage.list();

			const router = new Router();

			router.post('/exchangeAuthorizationCode', async request =>
				this.exchangeAuthorizationCode(request),
			);
			router.post('/persistAuthorizationCode', async request =>
				this.persistAuthorizationCode(request),
			);
			router.get('/jwks', async () => this.getJWKs());
			router.patch('/jwks', async () => this.cleanupJWKs());
			router.all('*', () => JsonResponse({ error: 'server_error' }, { status: 500 }));

			this.router = router;
		});
	}

	async fetch(request: Request): Promise<Response> {
		try {
			return await this.router.handle(request);
		} catch (error: unknown) {
			if (error instanceof Error) {
				console.error(error);
			}

			return JsonResponse({ error: 'server_error' }, { status: 500 });
		}
	}

	private async exchangeAuthorizationCode(request: RouterRequest): Promise<Response> {
		const { code } = await request.json<{ code?: string }>();
		if (code === undefined) {
			return JsonResponse(
				{
					error: 'invalid_request',
					error_description: 'missing required parameter(s) code',
				},
				{
					status: 400,
				},
			);
		}

		const authorizationCode = this.authorizationCodes.get(code);
		if (authorizationCode === undefined) {
			return JsonResponse(
				{ error: 'invalid_grant', error_description: 'grant request is invalid' },
				{
					status: 400,
				},
			);
		}

		// https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.5.4
		if (authorizationCode.usedAt !== undefined) {
			return JsonResponse(
				{ error: 'invalid_grant', error_description: 'grant request is invalid' },
				{
					status: 401,
				},
			);
		}

		// Mark the token as used, so it cannot be used again.
		// Ideally if a code is used twice we would revoke any tokens that were created,
		// which is why we keep track of the code usage rather than deleting it.
		authorizationCode.usedAt = new Date();
		this.authorizationCodes.set(code, authorizationCode);

		if (authorizationCode.expiresAt < new Date()) {
			return JsonResponse(
				{ error: 'invalid_grant', error_description: 'grant request is invalid' },
				{
					status: 401,
				},
			);
		}

		return JsonResponse(authorizationCode);
	}

	private async persistAuthorizationCode(request: RouterRequest): Promise<Response> {
		// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
		if (this.privateKey === undefined) {
			const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
			// @ts-expect-error
			const kid = crypto.randomUUID();

			this.privateKey = {
				id: kid,
				key: privateKey,
			};

			const jwk = await exportJWK(publicKey);
			jwk.kid = kid;

			const signingJWK: SigningJWK = {
				lastSignature: new Date(),
				jwk,
			};

			await this.storage.put(kid, signingJWK);
			this.jwks.set(kid, signingJWK);
		} else {
			const signingJWK = this.jwks.get(this.privateKey.id);
			if (signingJWK === undefined) {
				return JsonResponse({ error: 'server_error' }, { status: 500 });
			}

			signingJWK.lastSignature = new Date();
			await this.storage.put(this.privateKey.id, signingJWK);
			this.jwks.set(this.privateKey.id, signingJWK);
		}

		const {
			accessToken,
			code: _code,
			payload,
			responseType,
			exp,
		} = await request.json<PersistAuthorizationCode>();

		const header: JWTHeaderParameters = { alg: 'RS256', typ: 'JWT', kid: this.privateKey.id };

		// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
		// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation
		// https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		// NOTE: we do not generate the access_token, it is passed to us by Cloudflare Access,
		// at the time of writing it uses RS256 as the algorithm but the OpenID spec
		// tells us to use the algorithm from the id_token which we do generate.
		const atHash = await generate(
			accessToken,
			header.alg as SigningAlgorithm,
			header.crv as Curve,
		);

		let cHash: string | undefined;
		// https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		if (responseType.startsWith('code ')) {
			cHash = await generate(_code.code, header.alg as SigningAlgorithm, header.crv as Curve);
		}

		const idToken = await new SignJWT({ ...payload, at_hash: atHash, c_hash: cHash })
			.setProtectedHeader(header)
			.setIssuedAt() // iat
			.setExpirationTime('1h') // exp
			.sign(this.privateKey.key);

		const code: AuthorizationCode = {
			..._code,
			tokens: {
				accessToken,
				idToken,
				exp,
			},
		};
		this.authorizationCodes.set(code.code, code);

		return JsonResponse(code);
	}

	private async getJWKs(): Promise<Response> {
		const keys = [...this.jwks].map(([, jwk]) => jwk.jwk);

		return JsonResponse(keys);
	}

	// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	private async cleanupJWKs(): Promise<Response> {
		const expiry = new Date();
		expiry.setMinutes(expiry.getMinutes() - 10); // 10 minute TTL

		const keysToDelete: string[] = [];

		// eslint-disable-next-line unicorn/no-array-for-each
		this.jwks.forEach((jwk: SigningJWK, kid: string) => {
			if (this.privateKey?.id === kid) {
				return;
			}

			if (jwk.lastSignature > expiry) {
				return;
			}

			keysToDelete.push(kid);
			this.jwks.delete(kid);
		});

		if (keysToDelete.length > 0) {
			await this.storage.delete(keysToDelete);
		}

		return new Response(null, { status: 204 });
	}
}
