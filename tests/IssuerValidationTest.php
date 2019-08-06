<?php

namespace Endeavors\OpenJWT\Tests;

use PHPUnit\Framework\TestCase;
use Endeavors\OpenJWT\Inspect;
use Endeavors\OpenJWT\Validator\IssuerValidator;
use Firebase\JWT\JWT;

class IssuerValidationTest extends TestCase
{
    /**
     * @test
     */
    public function issuerValidates()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => "http://example.com",
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $this->assertEquals("portal", Inspect::issuer($jwt, "http://example.org")->sub);

        $validator = new IssuerValidator($jwt, "http://example.org");

        $validator->validate();
    }

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
