<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Contracts\Algorithm;
use Endeavors\OpenJWT\Exceptions\SignatureException;
use Endeavors\OpenJWT\Validator\Concerns\Decoding;
use UnexpectedValueException;
use InvalidArgumentException;
use Exception;
use ArrayAccess;

class SignatureValidator implements JWTValidator, Algorithm
{
    use Decoding;

    private $value;

    private $key;

    private $algorithm;

    public function __construct($value, $key, $algorithm = 'RS256')
    {
        $this->value = $value;

        $this->key = $key;

        $this->algorithm = $algorithm;
    }

    public function validate()
    {
        $function = key(static::SUPPORTED[$this->algorithm]);
        $algorithm = static::SUPPORTED[$this->algorithm][$function];

        $tks = explode('.', $this->value);

        list($headers, $payload, $signature) = $tks;

        $header = static::jsonDecode(static::urlsafeB64Decode($headers));
        $signature = static::urlsafeB64Decode($signature);

        if (is_array($this->key) || $this->key instanceof ArrayAccess) {
            if (isset($header->kid)) {
                if (!isset($this->key[$header->kid])) {
                    throw new UnexpectedValueException('"kid" invalid, unable to lookup correct key');
                }
                $this->key = $this->key[$header->kid];
            } else {
                throw new UnexpectedValueException('"kid" empty, unable to lookup correct key');
            }
        }

        switch($function) {
            case 'openssl':
                // if phpunit isn't configured to ignore warnings
                try {
                    $success = openssl_verify("$headers.$payload", $signature, $this->key, $algorithm);
                    if ($success === 0) {
                        throw SignatureException::failedVerification();
                    }
                } catch(Exception $e) {
                    throw SignatureException::failedCoercion();
                }
            case 'hash_hmac':
                $hash = hash_hmac($algorithm, "$headers.$payload", $this->key, true);
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
            default:
                throw SignatureException::unsupported();
        }
    }
}
