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

import { generateKeyPair as generate } from '../runtime/generate';
import type { KeyLike } from '../types';

interface GenerateKeyPairResult {
	/**
	 * The generated Private Key.
	 */
	privateKey: KeyLike;

	/**
	 * Public Key corresponding to the generated Private Key.
	 */
	publicKey: KeyLike;
}

interface GenerateKeyPairOptions {
	/**
	 * The EC "crv" (Curve) or OKP "crv" (Subtype of Key Pair) value to generate.
	 * The curve must be both supported on the runtime as well as applicable for
	 * the given JWA algorithm identifier.
	 */
	crv?: string;

	/**
	 * A hint for RSA algorithms to generate an RSA key of a given `modulusLength`
	 * (Key size in bits). JOSE requires 2048 bits or larger. Default is 2048.
	 */
	modulusLength?: number;

	/**
	 * (Web Cryptography API specific) The value to use as
	 * [SubtleCrypto.generateKey()](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey)
	 * `extractable` argument. Default is false.
	 */
	extractable?: boolean;
}

/**
 * Generates a private and a public key for a given JWA algorithm identifier.
 * This can only generate asymmetric key pairs. For symmetric secrets use the
 * `generateSecret` function.
 *
 * Note: Under Web Cryptography API runtime the `privateKey` is generated with
 * `extractable` set to `false` by default.
 *
 * @param alg JWA Algorithm Identifier to be used with the generated key pair.
 * @param options Additional options passed down to the key pair generation.
 *
 * @example Usage
 * ```js
 * const { publicKey, privateKey } = await jose.generateKeyPair('PS256')
 * console.log(publicKey)
 * console.log(privateKey)
 * ```
 */
async function generateKeyPair(
	alg: string,
	options?: GenerateKeyPairOptions,
): Promise<GenerateKeyPairResult> {
	return generate(alg, options);
}

export type { GenerateKeyPairOptions, GenerateKeyPairResult };
export { generateKeyPair };
