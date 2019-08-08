<?php

namespace Endeavors\OpenJWT\Validator;

use Endeavors\OpenJWT\Contracts\JWTValidator;
use LogicException;

class AggregateValidator implements JWTValidator
{
    private $validators = [];

    public function validate()
    {
        if (count($this->validators) === 0) {
            throw new LogicException("The AggregateValidator expects at least 1 validator.");
        }

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
