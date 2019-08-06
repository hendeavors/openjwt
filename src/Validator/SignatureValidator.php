<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Contracts\Algorithm;
use UnexpectedValueException;
use InvalidArgumentException;

class SignatureValidator implements JWTValidator, Algorithm
{
    private $value;

    private $key;

    public function __construct($value, $key)
    {
        $this->value = $value;

        $this->key = $key;
    }

    public function validate()
    {
        $function = key(static::SUPPORTED[$this->algorithm]);
        $algorithm = static::SUPPORTED[$this->algorithm][$function];

        $tks = explode('.', $this->value);

        list($headers, $payload, $signature) = $tks;

        switch($function) {
            case 'openssl':
                $success = openssl_verify($headers.$payload, $signature, $this->key, $algorithm);
                if ($success === 1) {
                    return true;
                } elseif ($success === 0) {
                    return false;
                }
                // returns 1 on success, 0 on failure, -1 on error.
                throw new InvalidArgumentException(
                    'OpenSSL error: ' . openssl_error_string()
                );
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $headers.$payload, $this->key, true);
                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }
                $len = min(mb_strlen($signature, '8bit'), mb_strlen($hash, '8bit'));
                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (ord($signature[$i]) ^ ord($hash[$i]));
                }
                $status |= (mb_strlen($signature, '8bit') ^ mb_strlen($hash, '8bit'));
                return ($status === 0);
        }

        throw new UnexpectedValueException('Signature verification failed');
    }
}
