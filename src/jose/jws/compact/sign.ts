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

import { CompactJWSHeaderParameters, KeyLike, SignOptions } from '../../types';
import { FlattenedSign } from '../flattened/sign';

/**
 * The CompactSign class is a utility for creating Compact JWS strings.
 *
 * @example Usage
 * ```js
 * const jws = await new jose.CompactSign(
 *   new TextEncoder().encode(
 *     'It’s a dangerous business, Frodo, going out your door.'
 *   )
 * )
 *   .setProtectedHeader({ alg: 'ES256' })
 *   .sign(privateKey)
 *
 * console.log(jws)
 * ```
 */
class CompactSign {
	private readonly _flattened: FlattenedSign;

	/**
	 * @param payload Binary representation of the payload to sign.
	 */
	constructor(payload: Uint8Array) {
		this._flattened = new FlattenedSign(payload);
	}

	/**
	 * Sets the JWS Protected Header on the Sign object.
	 *
	 * @param protectedHeader JWS Protected Header.
	 */
	setProtectedHeader(protectedHeader: CompactJWSHeaderParameters) {
		this._flattened.setProtectedHeader(protectedHeader);
		return this;
	}

	/**
	 * Signs and resolves the value of the Compact JWS string.
	 *
	 * @param key Private Key or Secret to sign the JWS with.
	 * @param options JWS Sign options.
	 */
	async sign(key: KeyLike | Uint8Array, options?: SignOptions): Promise<string> {
		const jws = await this._flattened.sign(key, options);

		if (jws.payload === undefined) {
			throw new TypeError('use the flattened module for creating JWS with b64: false');
		}

		return `${jws.protected ?? ''}.${jws.payload}.${jws.signature}`;
	}
}

export { CompactSign };
