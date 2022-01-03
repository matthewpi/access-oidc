/* eslint-disable @typescript-eslint/no-var-requires */
const { build } = require('esbuild');

const isProduction = process.env.NODE_ENV === 'production';

build({
	sourcemap: isProduction ? false : 'both',
	legalComments: 'none',
	format: 'esm',
	target: 'esnext',
	minify: isProduction,
	charset: 'utf8',
	logLevel: isProduction ? 'info' : 'silent',

	bundle: true,
	outfile: 'dist/index.mjs',
	entryPoints: ['src/index.ts'],
	platform: 'browser',
}).catch(() => process.exit(1));
