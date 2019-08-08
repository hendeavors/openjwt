<?php

namespace Endeavors\OpenJWT\Support;

function trim($t)
{
    return implode("\n", array_map('trim', explode("\n", $t)));
}
