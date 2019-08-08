<?php

namespace Endeavors\OpenJWT\Contracts;

interface JWTValidator
{
    /**
     * Validates
     * @return void
     */
    public function validate();
}
