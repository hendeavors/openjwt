<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Validator\Validator;
use Endeavors\OpenJWT\Validator\AuthorizedPartyValidator;
use DateTime;
use Endeavors\OpenJWT\Exceptions\IssuedAtException;

/**
 * iat claim validation
 */
class IssuedAtValidator extends Validator implements JWTValidator
{
    private $audience;

    private $value;

    public function __construct($value, int $timestamp)
    {
        $this->value = $value;

        $this->timestamp = $timestamp;
    }

    public function validate()
    {
        $tks = explode('.', $this->value);

        if (count($tks) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($headers, $payload, $signature) = $tks;

        $payload = static::jsonDecode(static::urlsafeB64Decode($payload));
        // iat is a NumericDate value in UTC
        if (property_exists($payload, 'iat') && (int)$payload->iat > $this->timestamp) {
            // reject the token
            throw new IssuedAtException('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat));
        }
    }
}
