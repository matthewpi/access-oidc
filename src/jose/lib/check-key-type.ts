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

import { isKeyLike, types } from '../runtime/is-key-like';
import { invalidKeyInput } from './invalid-key-input';

function symmetricTypeCheck(key: unknown) {
	if (key instanceof Uint8Array) {
		return;
	}

	if (!isKeyLike(key)) {
		throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
	}

	if (key.type !== 'secret') {
		throw new TypeError(
			`${types.join(' or ')} instances for symmetric algorithms must be of type "secret"`,
		);
	}
}

function asymmetricTypeCheck(key: unknown, usage: string) {
	if (!isKeyLike(key)) {
		throw new TypeError(invalidKeyInput(key, ...types));
	}

	if (key.type === 'secret') {
		throw new TypeError(
			`${types.join(
				' or ',
			)} instances for asymmetric algorithms must not be of type "secret"`,
		);
	}

	if (usage === 'sign' && key.type === 'public') {
		throw new TypeError(
			`${types.join(
				' or ',
			)} instances for asymmetric algorithm signing must be of type "private"`,
		);
	}

	if (usage === 'decrypt' && key.type === 'public') {
		throw new TypeError(
			`${types.join(
				' or ',
			)} instances for asymmetric algorithm decryption must be of type "private"`,
		);
	}

	// KeyObject allows this but CryptoKey does not.
	if ((key as CryptoKey).algorithm && usage === 'verify' && key.type === 'private') {
		throw new TypeError(
			`${types.join(
				' or ',
			)} instances for asymmetric algorithm verifying must be of type "public"`,
		);
	}

	// KeyObject allows this but CryptoKey does not.
	if ((key as CryptoKey).algorithm && usage === 'encrypt' && key.type === 'private') {
		throw new TypeError(
			`${types.join(
				' or ',
			)} instances for asymmetric algorithm encryption must be of type "public"`,
		);
	}
}

function checkKeyType(alg: string, key: unknown, usage: string) {
	const symmetric =
		alg.startsWith('HS') ||
		alg === 'dir' ||
		alg.startsWith('PBES2') ||
		/^A\d{3}(?:GCM)?KW$/.test(alg);

	if (symmetric) {
		symmetricTypeCheck(key);
	} else {
		asymmetricTypeCheck(key, usage);
	}
}

export { checkKeyType };
