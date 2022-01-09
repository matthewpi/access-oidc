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

import { JOSENotSupported, JWEInvalid, JWSInvalid } from '../errors';

interface CritCheckHeader {
	[propName: string]: unknown;

	b64?: boolean;
	crit?: string[];
}

function validateCrit(
	Error_: typeof JWEInvalid | typeof JWSInvalid,
	recognizedDefault: Map<string, boolean>,
	recognizedOption: Record<string, boolean> | undefined,
	protectedHeader: CritCheckHeader,
	joseHeader: CritCheckHeader,
) {
	if (joseHeader.crit !== undefined && protectedHeader.crit === undefined) {
		throw new Error_('"crit" (Critical) Header Parameter MUST be integrity protected');
	}

	if (!protectedHeader || protectedHeader.crit === undefined) {
		return new Set();
	}

	if (
		!Array.isArray(protectedHeader.crit) ||
		protectedHeader.crit.length === 0 ||
		protectedHeader.crit.some(
			(input: string) => typeof input !== 'string' || input.length === 0,
		)
	) {
		throw new Error_(
			'"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present',
		);
	}

	const recognized =
		recognizedOption === undefined
			? recognizedDefault
			: new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);

	for (const parameter of protectedHeader.crit) {
		if (!recognized.has(parameter)) {
			throw new JOSENotSupported(
				`Extension Header Parameter "${parameter}" is not recognized`,
			);
		}

		if (joseHeader[parameter] === undefined) {
			throw new Error_(`Extension Header Parameter "${parameter}" is missing`);
		} else if (recognized.get(parameter) && protectedHeader[parameter] === undefined) {
			throw new Error_(
				`Extension Header Parameter "${parameter}" MUST be integrity protected`,
			);
		}
	}

	return new Set(protectedHeader.crit);
}

export { validateCrit };
