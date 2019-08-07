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
    public function audience()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => "http://example.com",
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        JWT::$timestamp = [];

        $jwt = JWT::encode($token, $key);

        dump(JWT::decode($jwt, $key, ['HS256']));

        die;

        $this->assertEquals("portal", Inspect::audience($jwt, "http://example.com")->sub);

        $validator = new AudienceValidator($jwt, "http://example.com");

        $validator->validate();
    }

    /**
     * @test
     */
    public function multipleAudience()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "azp" => ["http://example.com", "http://google.com"],
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $this->assertEquals("portal", Inspect::audience($jwt, "http://example.com", "http://google.com")->sub);
    }
}
