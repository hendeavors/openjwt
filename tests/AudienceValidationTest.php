<?php

namespace Endeavors\OpenJWT\Tests;

use PHPUnit\Framework\TestCase;
use Endeavors\OpenJWT\Inspect;
use Endeavors\OpenJWT\Validator\AudienceValidator;
use Firebase\JWT\JWT;

class AudienceValidationTest extends TestCase
{
    /**
     * @test
     */
    public function audienceValidates()
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

        $this->assertEquals("portal", Inspect::audience($jwt, "http://example.com")->sub);

        $validator = new AudienceValidator($jwt, "http://example.com");

        $validator->validate();
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     */
    public function wrongNumberOfSegments()
    {
        $token = "test";

        Inspect::audience($token, "foo");
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     */
    public function validationWrongNumberOfSegments()
    {
        $validator = new AudienceValidator("test", "bar");

        $validator->validate();
    }
}
