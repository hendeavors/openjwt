<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use Endeavors\OpenJWT\Validator\Validator;
use Endeavors\OpenJWT\Validator\AuthorizedPartyValidator;
use UnexpectedValueException;

// The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the
// iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element.
// The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
// If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
// If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

class IssuedAtValidator extends Validator implements JWTValidator
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
