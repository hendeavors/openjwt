<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Validator\Validator;
use Endeavors\OpenJWT\Validator\AuthorizedPartyValidator;
use UnexpectedValueException;

/**
 * Validates the aud claim according to openid.net
 */
class AudienceValidator extends Validator implements JWTValidator
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

        if ($this->audience !== (array)$payload->aud) {
            // reject the token
            throw new UnexpectedValueException("The audience claim received does not match the given set of audiences");
        }

        (new AuthorizedPartyValidator($this->value, $this->audience))->validate();
    }
}
