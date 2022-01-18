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

import type { JWK, JWTPayload } from '../../jose';
import type { Env } from '../../types';
import type { AuthorizationCode } from '../authorization-code';
import type { ResponseType } from '../discovery';

export interface PersistAuthorizationCode {
	accessToken: string;
	code: Omit<AuthorizationCode, 'tokens'>;
	payload: JWTPayload;
	responseType: ResponseType;
	exp: number;
}

export interface StorageProvider {
	exchangeAuthorizationCode(env: Env, code: string): Promise<AuthorizationCode | Response>;
	persistAuthorizationCode(
		env: Env,
		request: PersistAuthorizationCode,
	): Promise<AuthorizationCode | Response>;
	getJWKs(env: Env): Promise<JWK[] | Response>;
	cleanupJWKs(env: Env): Promise<Response | undefined>;
}

export { durableObjectStorageProvider } from './durable-object';
