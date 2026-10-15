<?php

namespace Yasno\Logging\Tests\Support\Enum;

enum DeliveryChannel: string
{
    case Email = 'email';
    case Sms = 'sms';
}
