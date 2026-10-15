<?php

namespace Yasno\Logging\Tests\Support\Act;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernel;

final class KernelAct
{
    /** Serves a request the way php-fpm does: handle, send the response, terminate. */
    public static function serve(HttpKernel $kernel, ?Request $request = null): Response
    {
        $request ??= Request::create('/');
        $response = $kernel->handle($request);
        $kernel->terminate($request, $response);

        return $response;
    }
}
