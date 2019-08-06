<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Validator\Concerns\Decoding;
use UnexpectedValueException;

class IssuerValidator implements JWTValidator
{
    use Decoding;

    private $issuer;

    private $value;

    public function __construct($value, string $issuer)
    {
        $this->value = $value;

        $this->issuer = $issuer;
    }

    public function validate()
    {
        $tks = explode('.', $this->value);

        if (count($tks) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($headers, $payload, $signature) = $tks;

        $payload = static::jsonDecode(static::urlsafeB64Decode($payload));

        if ($payload->iss !== $this->issuer) {
            // reject the token
            throw new UnexpectedValueException("The audience claim received does not match the given set of audiences");
        }
    }
}
