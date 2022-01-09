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

import { JWTInvalid } from '../errors';
import { CompactSign } from '../jws/compact/sign';
import { encoder } from '../lib';
import { JWTHeaderParameters, KeyLike, SignOptions } from '../types';
import { ProduceJWT } from './produce';

/**
 * The SignJWT class is a utility for creating Compact JWS formatted JWT strings.
 *
 * @example Usage
 * ```js
 * const jwt = await new jose.SignJWT({ 'urn:example:claim': true })
 *   .setProtectedHeader({ alg: 'ES256' })
 *   .setIssuedAt()
 *   .setIssuer('urn:example:issuer')
 *   .setAudience('urn:example:audience')
 *   .setExpirationTime('2h')
 *   .sign(privateKey)
 *
 * console.log(jwt)
 * ```
 */
class SignJWT extends ProduceJWT {
	private _protectedHeader!: JWTHeaderParameters;

	/**
	 * Sets the JWS Protected Header on the SignJWT object.
	 *
	 * @param protectedHeader JWS Protected Header.
	 * Must contain an "alg" (JWS Algorithm) property.
	 */
	setProtectedHeader(protectedHeader: JWTHeaderParameters) {
		this._protectedHeader = protectedHeader;
		return this;
	}

	/**
	 * Signs and returns the JWT.
	 *
	 * @param key Private Key or Secret to sign the JWT with.
	 * @param options JWT Sign options.
	 */
	async sign(key: KeyLike | Uint8Array, options?: SignOptions): Promise<string> {
		const sig = new CompactSign(encoder.encode(JSON.stringify(this._payload)));
		sig.setProtectedHeader(this._protectedHeader);
		if (
			Array.isArray(this._protectedHeader?.crit) &&
			this._protectedHeader.crit.includes('b64') &&
			// @ts-expect-error
			this._protectedHeader.b64 === false
		) {
			throw new JWTInvalid('JWTs MUST NOT use unencoded payload');
		}
		return sig.sign(key, options);
	}
}

export { SignJWT };
