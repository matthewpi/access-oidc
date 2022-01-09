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

import { compactVerify } from '../jws/compact/verify';
import type {
	FlattenedJWSInput,
	JWTHeaderParameters,
	GetKeyFunction,
	VerifyOptions,
	JWTClaimVerificationOptions,
	JWTVerifyResult,
	KeyLike, ResolvedKey,
} from '../types';

/**
 * Combination of JWS Verification options and JWT Claims Set verification options.
 */
interface JWTVerifyOptions extends VerifyOptions, JWTClaimVerificationOptions {}

/**
 * Interface for JWT Verification dynamic key resolution.
 * No token components have been verified at the time of this function call.
 *
 * See [createRemoteJWKSet](../functions/jwks_remote.createRemoteJWKSet.md#function-createremotejwkset)
 * to verify using a remote JSON Web Key Set.
 */
interface JWTVerifyGetKey extends GetKeyFunction<JWTHeaderParameters, FlattenedJWSInput> {}

/**
 * Verifies the JWT format (to be a JWS Compact format), verifies the JWS signature, validates the JWT Claims Set.
 *
 * @param jwt JSON Web Token value (encoded as JWS).
 * @param key Key to verify the JWT with.
 * @param options JWT Decryption and JWT Claims Set validation options.
 *
 * @example Usage
 * ```js
 * const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6dHJ1ZSwiaWF0IjoxNjA0MzE1MDc0LCJpc3MiOiJ1cm46ZXhhbXBsZTppc3N1ZXIiLCJhdWQiOiJ1cm46ZXhhbXBsZTphdWRpZW5jZSJ9.hx1nOfAT5LlXuzu8O-bhjXBGpklWDt2EsHw7-MDn49NrnwvVsstNhEnkW2ddauB7eSikFtUNeumLpFI9CWDBsg'
 *
 * const { payload, protectedHeader } = await jose.jwtVerify(jwt, publicKey, {
 *   issuer: 'urn:example:issuer',
 *   audience: 'urn:example:audience'
 * })
 *
 * console.log(protectedHeader)
 * console.log(payload)
 * ```
 */
export async function jwtVerify(
	jwt: string | Uint8Array,
	key: KeyLike | Uint8Array | JWTVerifyGetKey,
	options?: JWTVerifyOptions,
): Promise<JWTVerifyResult & ResolvedKey> {
	const verified = await compactVerify(jwt, <Parameters<typeof compactVerify>[1]>key, options);
	if (verified.protectedHeader.crit?.includes('b64') && verified.protectedHeader.b64 === false) {
		throw new Error('JWTs MUST NOT use unencoded payload');
	}

	const payload = jwtPayload(verified.protectedHeader, verified.payload, options);
	const result = { payload, protectedHeader: verified.protectedHeader };
	if (typeof key === 'function') {
		return { ...result, key: verified.key };
	}
	return result;
}

export type { JWTVerifyOptions, JWTVerifyGetKey };
