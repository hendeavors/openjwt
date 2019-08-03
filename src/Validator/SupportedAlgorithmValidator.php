<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Contracts\Algorithm;
use InvalidArgumentException;

class SupportedAlgorithmValidator implements JWTValidator, Algorithm
{
    private $algorithm;

    public function __construct($algorithm)
    {
        $this->algorithm = $algorithm;
    }

    public function validate()
    {
        if (empty(static::SUPPORTED[$this->algorithm])) {
            throw new InvalidArgumentException('Algorithm not supported');
        }
    }
}
