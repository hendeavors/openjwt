<?php

namespace Endeavors\OpenJWT\Tests;

use PHPUnit\Framework\TestCase;
use Endeavors\OpenJWT\OpenIDToken;
use Endeavors\OpenJWT\Validator\AudienceValidator;
use Firebase\JWT\JWT;

class OpenIDValidationTest extends TestCase
{
    /**
     * @test
     */
    public function singleAudience()
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
        ->server("http://example.org")
        ->decode();

        $this->assertEquals("portal", $token->sub);
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

        $token = OpenIDToken::create($jwt)
        ->client("http://example.com", "http://google.com")
        ->requestedAt(time())
        ->server("http://example.org")
        ->decode();

        $this->assertEquals("portal", $token->sub);
    }
}
