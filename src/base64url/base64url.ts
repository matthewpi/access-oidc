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

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function encodeBase64(input: Uint8Array | string): string {
	let unencoded = input;
	if (typeof unencoded === 'string') {
		unencoded = encoder.encode(unencoded);
	}

	const CHUNK_SIZE = 0x80_00;
	const array = [];
	for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
		// @ts-expect-error go away
		array.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
	}

	return btoa(array.join(''));
}

function encode(input: Uint8Array | string) {
	return encodeBase64(input).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function decodeBase64(encoded: string): Uint8Array {
	// eslint-disable-next-line unicorn/prefer-code-point
	return new Uint8Array([...atob(encoded)].map(c => c.charCodeAt(0)));
}

function decode(input: Uint8Array | string) {
	let encoded = input;
	if (encoded instanceof Uint8Array) {
		encoded = decoder.decode(encoded);
	}

	encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
	try {
		return decodeBase64(encoded);
	} catch {
		throw new TypeError('The input to be decoded is not correctly encoded.');
	}
}

export { decode, encode };
