<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Validator\Validator;
use UnexpectedValueException;

/**
 * Validate an azp claim if one exists
 */
class AuthorizedPartyValidator extends Validator implements JWTValidator
{
    private $audience;

    private $value;

    public function __construct($value, $audience)
    {
        $this->value = $value;

        $this->audience = (array)$audience;
    }

    public function validate()
    {
        $tks = explode('.', $this->value);

        if (count($tks) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($headers, $payload, $signature) = $tks;

        $payload = static::jsonDecode(static::urlsafeB64Decode($payload));

        if (count((array)$payload->aud) > 1 && !property_exists($payload, 'azp')) {
            throw new UnexpectedValueException("An authorized party claim must be present.");
        }

        if (property_exists($payload, 'azp') && null === $payload->azp && count((array)$payload->aud) > 1) {
            throw new UnexpectedValueException("The authorized party claim is not valid.");
        }

        if (property_exists($payload, 'azp') && $this->audience !== (array)$payload->azp) {
            // reject the token
            throw new UnexpectedValueException("The authorized party received does not match the given set of audiences");
        }
    }
}
