<?php

namespace Endeavors\OpenJWT\Tests;

use PHPUnit\Framework\TestCase;
use Endeavors\OpenJWT\OpenIDToken;
use Endeavors\OpenJWT\Validator\AudienceValidator;
use Firebase\JWT\JWT;

class OpenIDValidationUsageTest extends TestCase
{
    /**
     * @test
     */
    public function doubleCalls()
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

        $token = OpenIDToken::create($jwt)
        ->requestedAt(time())
        ->client("http://example.com")
        ->client("http://example.com")
        ->provider("http://example.org")
        ->provider("http://example.org")
        ->decode();

        $this->assertEquals("portal", $token->sub);
    }
}
