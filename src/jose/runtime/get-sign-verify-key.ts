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

import { checkSigCryptoKey } from '../lib/crypto-key';
import { invalidKeyInput } from '../lib/invalid-key-input';
import { types } from './is-key-like';
import { isCryptoKey } from './webcrypto';

function getSignVerifyKey(alg: string, key: unknown, usage: KeyUsage) {
	if (isCryptoKey(key)) {
		checkSigCryptoKey(key, alg, usage);
		return key;
	}

	if (key instanceof Uint8Array) {
		if (!alg.startsWith('HS')) {
			throw new TypeError(invalidKeyInput(key, ...types));
		}
		return crypto.subtle.importKey(
			'raw',
			key,
			{ hash: `SHA-${alg.slice(-3)}`, name: 'HMAC' },
			false,
			[usage],
		);
	}

	throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
}

export { getSignVerifyKey };
