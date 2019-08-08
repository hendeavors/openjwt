<?php

namespace Endeavors\OpenJWT\Exceptions;

use RuntimeException;

class SignatureException extends RuntimeException
{
    public static function failedCoercion()
    {
        return new static("openssl_verify(): Supplied key param cannot be coerced into a public key", 1);
    }

    public static function failedVerification()
    {
        return new static("Signature verification failed", 2);
    }

    public static function unsupported()
    {
        return new static(sprintf("Unable to use %s or %s to verify the signature.", 'openssl_verify', 'hash_hmac'));
    }
}
