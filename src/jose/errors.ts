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

/**
 * A generic Error subclass that all other specific
 * JOSE Error subclasses inherit from.
 */
class JOSEError extends Error {
	/**
	 * A unique error code for the particular error subclass.
	 */
	static get code(): string {
		return 'ERR_JOSE_GENERIC';
	}

	/**
	 * A unique error code for the particular error subclass.
	 */
	code = 'ERR_JOSE_GENERIC';

	constructor(message?: string) {
		super(message);
		this.name = this.constructor.name;
		// Error.captureStackTrace?.(this, this.constructor);
	}
}

/**
 * An error subclass thrown when a JWT Claim Set member validation fails.
 */
class JWTClaimValidationFailed extends JOSEError {
	static override get code(): 'ERR_JWT_CLAIM_VALIDATION_FAILED' {
		return 'ERR_JWT_CLAIM_VALIDATION_FAILED';
	}

	override code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';

	/**
	 * The Claim for which the validation failed.
	 */
	claim: string;

	/**
	 * Reason code for the validation failure.
	 */
	reason: string;

	constructor(message: string, claim = 'unspecified', reason = 'unspecified') {
		super(message);
		this.claim = claim;
		this.reason = reason;
	}
}

/**
 * An error subclass thrown when a JWT is expired.
 */
class JWTExpired extends JOSEError implements JWTClaimValidationFailed {
	static override get code(): 'ERR_JWT_EXPIRED' {
		return 'ERR_JWT_EXPIRED';
	}

	override code = 'ERR_JWT_EXPIRED';

	/**
	 * The Claim for which the validation failed.
	 */
	claim: string;

	/**
	 * Reason code for the validation failure.
	 */
	reason: string;

	constructor(message: string, claim = 'unspecified', reason = 'unspecified') {
		super(message);
		this.claim = claim;
		this.reason = reason;
	}
}

/**
 * An error subclass thrown when a JOSE Algorithm is not allowed per developer preference.
 */
class JOSEAlgNotAllowed extends JOSEError {
	static override get code(): 'ERR_JOSE_ALG_NOT_ALLOWED' {
		return 'ERR_JOSE_ALG_NOT_ALLOWED';
	}

	override code = 'ERR_JOSE_ALG_NOT_ALLOWED';
}

/**
 * An error subclass thrown when a particular feature or algorithm is not supported by this
 * implementation or JOSE in general.
 */
class JOSENotSupported extends JOSEError {
	static override get code(): 'ERR_JOSE_NOT_SUPPORTED' {
		return 'ERR_JOSE_NOT_SUPPORTED';
	}

	override code = 'ERR_JOSE_NOT_SUPPORTED';
}

/**
 * An error subclass thrown when a JWE ciphertext decryption fails.
 */
class JWEDecryptionFailed extends JOSEError {
	static override get code(): 'ERR_JWE_DECRYPTION_FAILED' {
		return 'ERR_JWE_DECRYPTION_FAILED';
	}

	override code = 'ERR_JWE_DECRYPTION_FAILED';

	override message = 'decryption operation failed';
}

/**
 * An error subclass thrown when a JWE is invalid.
 */
class JWEInvalid extends JOSEError {
	static override get code(): 'ERR_JWE_INVALID' {
		return 'ERR_JWE_INVALID';
	}

	override code = 'ERR_JWE_INVALID';
}

/**
 * An error subclass thrown when a JWS is invalid.
 */
class JWSInvalid extends JOSEError {
	static override get code(): 'ERR_JWS_INVALID' {
		return 'ERR_JWS_INVALID';
	}

	override code = 'ERR_JWS_INVALID';
}

/**
 * An error subclass thrown when a JWT is invalid.
 */
class JWTInvalid extends JOSEError {
	static override get code(): 'ERR_JWT_INVALID' {
		return 'ERR_JWT_INVALID';
	}

	override code = 'ERR_JWT_INVALID';
}

/**
 * An error subclass thrown when a JWK is invalid.
 */
class JWKInvalid extends JOSEError {
	static override get code(): 'ERR_JWK_INVALID' {
		return 'ERR_JWK_INVALID';
	}

	override code = 'ERR_JWK_INVALID';
}

/**
 * An error subclass thrown when a JWKS is invalid.
 */
class JWKSInvalid extends JOSEError {
	static override get code(): 'ERR_JWKS_INVALID' {
		return 'ERR_JWKS_INVALID';
	}

	override code = 'ERR_JWKS_INVALID';
}

/**
 * An error subclass thrown when no keys match from a JWKS.
 */
class JWKSNoMatchingKey extends JOSEError {
	static override get code(): 'ERR_JWKS_NO_MATCHING_KEY' {
		return 'ERR_JWKS_NO_MATCHING_KEY';
	}

	override code = 'ERR_JWKS_NO_MATCHING_KEY';

	override message = 'no applicable key found in the JSON Web Key Set';
}

/**
 * An error subclass thrown when multiple keys match from a JWKS.
 */
class JWKSMultipleMatchingKeys extends JOSEError {
	static override get code(): 'ERR_JWKS_MULTIPLE_MATCHING_KEYS' {
		return 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';
	}

	override code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';

	override message = 'multiple matching keys found in the JSON Web Key Set';
}

/**
 * Timeout was reached when retrieving the JWKS response.
 */
class JWKSTimeout extends JOSEError {
	static override get code(): 'ERR_JWKS_TIMEOUT' {
		return 'ERR_JWKS_TIMEOUT';
	}

	override code = 'ERR_JWKS_TIMEOUT';

	override message = 'request timed out';
}

/**
 * An error subclass thrown when JWS signature verification fails.
 */
class JWSSignatureVerificationFailed extends JOSEError {
	static override get code(): 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' {
		return 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
	}

	override code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';

	override message = 'signature verification failed';
}

export {
	JOSEAlgNotAllowed,
	JOSENotSupported,
	JOSEError,
	JWEDecryptionFailed,
	JWEInvalid,
	JWKSInvalid,
	JWKInvalid,
	JWKSMultipleMatchingKeys,
	JWKSNoMatchingKey,
	JWSInvalid,
	JWSSignatureVerificationFailed,
	JWTInvalid,
	JWKSTimeout,
	JWTClaimValidationFailed,
	JWTExpired,
};
