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

const minute = 60;
const hour = minute * 60;
const day = hour * 24;
const week = day * 7;
const year = day * 365.25;

const REGEX =
	/^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i;

function secs(string_: string): number {
	const matched = REGEX.exec(string_);

	if (!matched) {
		throw new TypeError('Invalid time period format');
	}

	const value = Number.parseFloat(matched[1]);
	const unit = matched[2].toLowerCase();

	switch (unit) {
		case 'sec':
		case 'secs':
		case 'second':
		case 'seconds':
		case 's':
			return Math.round(value);
		case 'minute':
		case 'minutes':
		case 'min':
		case 'mins':
		case 'm':
			return Math.round(value * minute);
		case 'hour':
		case 'hours':
		case 'hr':
		case 'hrs':
		case 'h':
			return Math.round(value * hour);
		case 'day':
		case 'days':
		case 'd':
			return Math.round(value * day);
		case 'week':
		case 'weeks':
		case 'w':
			return Math.round(value * week);
		// years matched
		default:
			return Math.round(value * year);
	}
}

export { secs };
