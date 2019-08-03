<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;

class AudienceValidator implements JWTValidator
{
    public function validate()
    {
        // we are only inspecting the token
    }
}
