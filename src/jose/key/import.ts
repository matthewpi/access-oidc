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

import { decode as decodeBase64URL } from '../../base64url';
import { JOSENotSupported } from '../errors';
import { isObject } from '../lib';
import { jwkToKey } from '../runtime/jwk-to-key';
import type { JWK, KeyLike } from '../types';

/**
 * Imports a JWK to a runtime-specific key representation (KeyLike). Either
 * JWK "alg" (Algorithm) Parameter must be present or the optional "alg" argument. When
 * running on a runtime using [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
 * the jwk parameters "use", "key_ops", and "ext" are also used in the resulting `CryptoKey`.
 * See [Algorithm Key Requirements](https://github.com/panva/jose/issues/210) to learn about key to algorithm
 * requirements and mapping.
 *
 * @param jwk JSON Web Key.
 * @param alg JSON Web Algorithm identifier to be used with the imported key.
 * Default is the "alg" property on the JWK.
 * @param octAsKeyObject Forces a symmetric key to be imported to a KeyObject or
 * CryptoKey. Default is true unless JWK "ext" (Extractable) is true.
 *
 * @example Usage
 * ```js
 * const ecPublicKey = await jose.importJWK({
 *   crv: 'P-256',
 *   kty: 'EC',
 *   x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
 *   y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo'
 * }, 'ES256')
 *
 * const rsaPublicKey = await jose.importJWK({
 *   kty: 'RSA',
 *   e: 'AQAB',
 *   n: '12oBZRhCiZFJLcPg59LkZZ9mdhSMTKAQZYq32k_ti5SBB6jerkh-WzOMAO664r_qyLkqHUSp3u5SbXtseZEpN3XPWGKSxjsy-1JyEFTdLSYe6f9gfrmxkUF_7DTpq0gn6rntP05g2-wFW50YO7mosfdslfrTJYWHFhJALabAeYirYD7-9kqq9ebfFMF4sRRELbv9oi36As6Q9B3Qb5_C1rAzqfao_PCsf9EPsTZsVVVkA5qoIAr47lo1ipfiBPxUCCNSdvkmDTYgvvRm6ZoMjFbvOtgyts55fXKdMWv7I9HMD5HwE9uW839PWA514qhbcIsXEYSFMPMV6fnlsiZvQQ'
 * }, 'PS256')
 * ```
 */
async function importJWK(
	jwk: JWK,
	alg?: string,
	octAsKeyObject?: boolean,
): Promise<KeyLike | Uint8Array> {
	if (!isObject(jwk)) {
		throw new TypeError('JWK must be an object');
	}

	alg ||= jwk.alg;

	if (typeof alg !== 'string' || !alg) {
		throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
	}

	switch (jwk.kty) {
		case 'oct':
			if (typeof jwk.k !== 'string' || !jwk.k) {
				throw new TypeError('missing "k" (Key Value) Parameter value');
			}

			octAsKeyObject ??= jwk.ext !== true;

			if (octAsKeyObject) {
				return jwkToKey({ ...jwk, alg, ext: false });
			}

			return decodeBase64URL(jwk.k);
		// @ts-expect-error
		case 'RSA':
			if (jwk.oth !== undefined) {
				throw new JOSENotSupported(
					'RSA JWK "oth" (Other Primes Info) Parameter value is not supported',
				);
			}
		case 'EC':
		case 'OKP':
			return jwkToKey({ ...jwk, alg });
		default:
			throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
	}
}

export { importJWK };
