<?php

namespace Endeavors\OpenJWT\Tests;

use PHPUnit\Framework\TestCase;
use Endeavors\OpenJWT\Inspect;
use Endeavors\OpenJWT\Validator\IssuerValidator;
use Firebase\JWT\JWT;

class IssuerValidationFailureTest extends TestCase
{
    /**
     * @test
     * @expectedException \UnexpectedValueException
     */
    public function wrongNumberOfSegments()
    {
        $token = "test";

        Inspect::issuer($token, "http://example.org");
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     */
    public function validationWrongNumberOfSegments()
    {
        $validator = new IssuerValidator("test", "http://example.org");

        $validator->validate();
    }
}
