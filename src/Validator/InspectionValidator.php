<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;

class InspectionValidator implements JWTValidator
{
    public function validate()
    {
        // we are only inspecting the token
    }
}
