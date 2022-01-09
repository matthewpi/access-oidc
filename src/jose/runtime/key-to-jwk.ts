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

import { encode as encodeBase64URL } from '../../base64url';
import { invalidKeyInput } from '../lib/invalid-key-input';
import type { JWK } from '../types';
import { types } from './is-key-like';
import { isCryptoKey } from './webcrypto';

async function keyToJWK(key: unknown): Promise<JWK> {
	if (key instanceof Uint8Array) {
		return {
			kty: 'oct',
			k: encodeBase64URL(key),
		};
	}

	if (!isCryptoKey(key)) {
		throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
	}

	if (!key.extractable) {
		throw new TypeError('non-extractable CryptoKey cannot be exported as a JWK');
	}

	const { ext, key_ops, alg, use, ...jwk } = await crypto.subtle.exportKey('jwk', key);

	return jwk as JWK;
}

export { keyToJWK };
