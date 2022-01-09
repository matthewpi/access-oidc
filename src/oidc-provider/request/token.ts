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

import { decode } from '../../base64url';

import type { GrantType } from '../discovery';
import type { TokenError } from '../error';

export interface TokenRequestBody {
	clientId?: string;
	clientSecret?: string;
	redirectUri: string;
	code: string;
	grantType: GrantType;
	codeVerifier?: string;
}

export function getTokenRequestBody(data: FormData): TokenRequestBody | TokenError {
	if (!data.has('redirect_uri')) {
		return {
			error: 'invalid_request',
			error_description: 'missing required parameter(s) redirect_uri',
		};
	}

	let redirectUri: string;
	try {
		redirectUri = new URL(data.get('redirect_uri') as string).toString();
	} catch {
		return {
			error: 'invalid_request',
			error_description: 'invalid or malformed redirect_uri',
		};
	}

	if (!data.has('code')) {
		return {
			error: 'invalid_request',
			error_description: 'missing required parameter(s) code',
		};
	}

	if (!data.has('grant_type')) {
		return {
			error: 'invalid_request',
			error_description: 'missing required parameter(s) grant_type',
		};
	}

	const grantType = data.get('grant_type') as string;
	if (grantType !== 'authorization_code') {
		return {
			error: 'unsupported_grant_type',
		};
	}

	let codeVerifier: string | undefined;
	if (data.has('code_verifier')) {
		codeVerifier = data.get('code_verifier') as string;
	}

	return {
		clientId: data.has('client_id') ? (data.get('client_id') as string) : undefined,
		clientSecret: data.has('client_secret') ? (data.get('client_secret') as string) : undefined,
		redirectUri,
		code: data.get('code') as string,
		grantType,
		codeVerifier,
	};
}

export interface TokenAuthorization {
	clientId: string;
	clientSecret: string;
}

export function parseTokenAuthorization(header: string): TokenAuthorization | TokenError {
	if (!header.startsWith('Basic ')) {
		return {
			error: 'invalid_request',
			error_description: 'invalid authorization header value format',
		};
	}

	const decoded = decode(header.slice('Basic '.length));
	const headerString = String.fromCodePoint(...decoded);
	const authParts = headerString.split(':');
	if (authParts.length !== 2) {
		return {
			error: 'invalid_request',
			error_description: 'invalid authorization header value format',
		};
	}

	return { clientId: authParts[0], clientSecret: authParts[1] };
}
