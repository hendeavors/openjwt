<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;

class AggregateValidator implements JWTValidator
{
    private $validators = [];

    public function validate()
    {
        foreach($this->validators as $validator) {
            $validator->validate();
        }
    }

    public function add(JWTValidator $validator)
    {
        $this->validators[] = $validator;

        return $this;
    }
}
