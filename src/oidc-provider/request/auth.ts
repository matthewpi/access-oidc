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

import type { Params } from '../../router';
import type { Env } from '../../types';
import type { ResponseType } from '../discovery';
import type { AuthorizationError } from '../error';
import type { ChallengeMethod } from '../pkce';
import type { Client } from './client-registration';

export interface AuthRequestQuery {
	clientId: string;
	redirectUri: string;
	responseType: ResponseType;
	scopes: string[];
	state?: string;
	nonce?: string;
	// display?: string;
	// prompt?: string;
	// uiLocales?: string[];
	// idTokenHint?: string[];
	// loginHint?: string;
	// acrValues?: string[];
	codeChallenge?: {
		method: ChallengeMethod;
		challenge: string;
	};
}

export async function getAuthRequestQuery(
	query: Params,
	env: Env,
): Promise<AuthRequestQuery | AuthorizationError> {
	if (query.client_id === undefined) {
		return {
			error: 'invalid_request',
			error_description: 'missing required parameter(s) client_id',
		};
	}

	if (query.redirect_uri === undefined) {
		return {
			error: 'invalid_request',
			error_description: 'missing required parameter(s) redirect_uri',
		};
	}

	let redirectUri: string;
	try {
		redirectUri = new URL(query.redirect_uri).toString();
	} catch {
		return {
			error: 'invalid_request',
			error_description: 'invalid or malformed redirect_uri',
		};
	}

	const client = await env.KV_OIDC.get<Client>('clients:' + query.client_id, 'json');
	if (client === null) {
		return {
			error: 'invalid_request',
			error_description: 'resource not found',
		};
	}

	if (!client.redirectUris.includes(redirectUri)) {
		return {
			error: 'invalid_request',
			error_description: 'unregistered redirect_uri',
		};
	}

	if (query.response_type === undefined) {
		return {
			error: 'invalid_request',
			error_description: 'missing required parameter(s) response_type',
			state: query.state,
			redirectUri,
		};
	}

	if (query.scope === undefined) {
		return {
			error: 'invalid_request',
			error_description: 'missing required parameter(s) scope',
			state: query.state,
			redirectUri,
		};
	}

	const scopes = query.scope.split(' ');
	if (!scopes.includes('openid')) {
		return {
			error: 'invalid_scope',
			error_description: 'missing required scope(s) openid',
			state: query.state,
			redirectUri,
		};
	}

	// https://openid.net/specs/openid-connect-core-1_0.html#Authentication
	switch (query.response_type) {
		// https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
		case 'code':
			break;

		// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthorizationEndpoint
		case 'id_token':
		case 'id_token token':
			if (query.nonce === undefined) {
				return {
					error: 'invalid_request',
					error_description: 'missing required parameter(s) nonce',
					state: query.state,
					redirectUri,
				};
			}

			break;

		// https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthorizationEndpoint
		case 'code id_token':
		case 'code id_token token':
			break;

		default:
			return {
				error: 'unsupported_response_type',
				error_description: 'the specified response_type is not supported',
				state: query.state,
				redirectUri,
			};
	}

	let codeChallengeMethod: ChallengeMethod | undefined;
	if (query.code_challenge !== undefined) {
		codeChallengeMethod = query.code_challenge_method === 'S256' ? 'S256' : 'plain';
	}

	return {
		clientId: query.client_id,
		redirectUri,
		responseType: query.response_type,
		scopes,
		state: query.state,
		nonce: query.nonce,
		codeChallenge:
			codeChallengeMethod === undefined
				? undefined
				: {
						method: codeChallengeMethod,
						challenge: query.code_challenge,
				  },
	};
}
