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

import type { JWTVerifyResult } from './jose';
import { createRemoteJWKSet, jwtVerify } from './jose';
import type { Env } from './types';

export interface AccessIdentity {
	id: string;
	email: string;
	name: string;
	givenName: string;
	surName: string;
	idp: {
		id: string;
		type: string;
	};
	geo: {
		country: string;
	};
	user_uuid: string;
	account_id: string;
	ip: string;
	auth_status: string;
	common_name: string;
	service_token_id: string;
	service_token_status: boolean;
	is_warp: boolean;
	is_gateway: boolean;
	version: number;
	device_sessions: unknown[];
	iat: number;
	custom?: Record<string, any>;
}

export interface AccessError {
	err: string;
}

export type AccessIdentityResponse = AccessIdentity | AccessError;

export class API {
	private readonly env: Env;

	constructor(env: Env) {
		this.env = env;
	}

	async getCloudflareAccessIdentity(accessToken: string): Promise<AccessIdentityResponse> {
		const response = await this.getAccess('/get-identity', {
			headers: {
				cookie: `CF_Authorization=${accessToken}`,
			},
		});

		return response.json();
	}

	async verifyCloudflareAccessJWT(jwt: string): Promise<JWTVerifyResult> {
		return jwtVerify(jwt, this.remoteJWKSet(), {
			issuer: this.getAccessBaseUrl(),
			audience: this.env.SECRET_CF_ACCESS_AUD,
		});
	}

	private remoteJWKSet(): any {
		return createRemoteJWKSet(new URL(this.getAccessUri('/certs')));
	}

	private async getAccess(uri: string, requestInitr?: RequestInit | Request): Promise<Response> {
		return fetch(this.getAccessUri(uri), requestInitr);
	}

	private getAccessUri(uri: string): string {
		return `${this.getAccessBaseUrl()}/cdn-cgi/access${uri}`;
	}

	private getAccessBaseUrl(): string {
		return `https://${this.env.SECRET_CF_ACCESS_TEAM}.cloudflareaccess.com`;
	}
}
