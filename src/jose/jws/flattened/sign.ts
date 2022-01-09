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

import { encode as encodeBase64URL } from '../../../base64url';
import { JWSInvalid } from '../../errors';
import { concat, decoder, encoder, isDisjoint } from '../../lib';
import { checkKeyType } from '../../lib/check-key-type';
import { validateCrit } from '../../lib/validate-crit';
import { sign } from '../../runtime/sign';
import { FlattenedJWS, JWSHeaderParameters, KeyLike, SignOptions } from '../../types';

/**
 * The FlattenedSign class is a utility for creating Flattened JWS objects.
 *
 * @example Usage
 * ```js
 * const jws = await new jose.FlattenedSign(
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
class FlattenedSign {
	private readonly _payload: Uint8Array;

	private _protectedHeader!: JWSHeaderParameters;

	private _unprotectedHeader!: JWSHeaderParameters;

	/**
	 * @param payload Binary representation of the payload to sign.
	 */
	constructor(payload: Uint8Array) {
		if (!(payload instanceof Uint8Array)) {
			throw new TypeError('payload must be an instance of Uint8Array');
		}

		this._payload = payload;
	}

	/**
	 * Sets the JWS Protected Header on the FlattenedSign object.
	 *
	 * @param protectedHeader JWS Protected Header.
	 */
	setProtectedHeader(protectedHeader: JWSHeaderParameters) {
		if (this._protectedHeader) {
			throw new TypeError('setProtectedHeader can only be called once');
		}

		this._protectedHeader = protectedHeader;
		return this;
	}

	/**
	 * Sets the JWS Unprotected Header on the FlattenedSign object.
	 *
	 * @param unprotectedHeader JWS Unprotected Header.
	 */
	setUnprotectedHeader(unprotectedHeader: JWSHeaderParameters) {
		if (this._unprotectedHeader) {
			throw new TypeError('setUnprotectedHeader can only be called once');
		}

		this._unprotectedHeader = unprotectedHeader;
		return this;
	}

	/**
	 * Signs and resolves the value of the Flattened JWS object.
	 *
	 * @param key Private Key or Secret to sign the JWS with.
	 * @param options JWS Sign options.
	 */
	async sign(key: KeyLike | Uint8Array, options?: SignOptions): Promise<FlattenedJWS> {
		if (!this._protectedHeader && !this._unprotectedHeader) {
			throw new JWSInvalid(
				'either setProtectedHeader or setUnprotectedHeader must be called before #sign()',
			);
		}

		if (!isDisjoint(this._protectedHeader, this._unprotectedHeader)) {
			throw new JWSInvalid(
				'JWS Protected and JWS Unprotected Header Parameter names must be disjoint',
			);
		}

		const joseHeader: JWSHeaderParameters = {
			...this._protectedHeader,
			...this._unprotectedHeader,
		};

		const extensions = validateCrit(
			JWSInvalid,
			new Map([['b64', true]]),
			options?.crit,
			this._protectedHeader,
			joseHeader,
		);

		let b64 = true;
		if (extensions.has('b64')) {
			b64 = this._protectedHeader.b64!;
			if (typeof b64 !== 'boolean') {
				throw new JWSInvalid(
					'The "b64" (base64url-encode payload) Header Parameter must be a boolean',
				);
			}
		}

		const { alg } = joseHeader;

		if (typeof alg !== 'string' || !alg) {
			throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
		}

		checkKeyType(alg, key, 'sign');

		let payload = this._payload;
		if (b64) {
			payload = encoder.encode(encodeBase64URL(payload));
		}

		let protectedHeader: Uint8Array;
		if (this._protectedHeader) {
			protectedHeader = encoder.encode(
				encodeBase64URL(JSON.stringify(this._protectedHeader)),
			);
		} else {
			protectedHeader = encoder.encode('');
		}

		const data = concat(protectedHeader, encoder.encode('.'), payload);

		const signature = await sign(alg, key, data);

		const jws: FlattenedJWS = {
			signature: encodeBase64URL(signature),
			payload: '',
		};

		if (b64) {
			jws.payload = decoder.decode(payload);
		}

		if (this._unprotectedHeader) {
			jws.header = this._unprotectedHeader;
		}

		if (this._protectedHeader) {
			jws.protected = decoder.decode(protectedHeader);
		}

		return jws;
	}
}

export { FlattenedSign };
