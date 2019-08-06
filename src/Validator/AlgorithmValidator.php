<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Contracts\Algorithm;
use Endeavors\OpenJWT\Validator\Concerns\Decoding;
use UnexpectedValueException;

class AlgorithmValidator implements JWTValidator, Algorithm
{
    use Decoding;

    private $value;

    public function __construct($value)
    {
        $this->value = $value;
    }

    public function validate()
    {
        $tks = explode('.', $this->value);

        if (count($tks) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($headers, $payload, $signature) = $tks;

        $headers = static::jsonDecode(static::urlsafeB64Decode($headers));

        if (empty(static::SUPPORTED[$headers->alg])) {
            throw new UnexpectedValueException(sprintf('Algorithm [%s] not supported', $headers->alg));
        }
    }
}
