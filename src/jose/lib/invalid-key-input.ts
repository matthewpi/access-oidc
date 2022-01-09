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

function invalidKeyInput(actual: unknown, ...types: string[]): string {
	let msg = 'Key must be ';

	if (types.length > 2) {
		const last = types.pop();
		msg += `one of type ${types.join(', ')}, or ${last}.`;
	} else if (types.length === 2) {
		msg += `one of type ${types[0]} or ${types[1]}.`;
	} else {
		msg += `of type ${types[0]}.`;
	}

	if (actual == null) {
		msg += ` Received ${actual}`;
	} else if (typeof actual === 'function' && actual.name) {
		msg += ` Received function ${actual.name}`;
	} else if (typeof actual === 'object' && actual != null) {
		if (actual.constructor && actual.constructor.name) {
			msg += ` Received an instance of ${actual.constructor.name}`;
		}
	}

	return msg;
}

export { invalidKeyInput };
