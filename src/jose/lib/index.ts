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

function concat(...buffers: Uint8Array[]): Uint8Array {
	const size = buffers.reduce((acc, { length }) => acc + length, 0);
	const buf = new Uint8Array(size);
	let i = 0;
	buffers.forEach(buffer => {
		buf.set(buffer, i);
		i += buffer.length;
	});
	return buf;
}

function isObjectLike(value: unknown) {
	return typeof value === 'object' && value !== null;
}

function isObject<T = object>(input: unknown): input is T {
	if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
		return false;
	}
	if (Object.getPrototypeOf(input) === null) {
		return true;
	}
	let proto = input;
	while (Object.getPrototypeOf(proto) !== null) {
		proto = Object.getPrototypeOf(proto);
	}
	return Object.getPrototypeOf(input) === proto;
}

function isDisjoint(...headers: Array<object | undefined>) {
	const sources = <object[]>headers.filter(Boolean);

	if (sources.length === 0 || sources.length === 1) {
		return true;
	}

	let acc!: Set<string>;
	for (const header of sources) {
		const parameters = Object.keys(header);
		if (!acc || acc.size === 0) {
			acc = new Set(parameters);
			continue;
		}

		for (const parameter of parameters) {
			if (acc.has(parameter)) {
				return false;
			}
			acc.add(parameter);
		}
	}

	return true;
}

export { encoder, decoder, concat, isDisjoint, isObject };
