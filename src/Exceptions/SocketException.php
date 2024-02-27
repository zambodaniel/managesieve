<?php
/**
 * Created by PhpStorm.
 * User: zdaniel
 * Date: 2018.08.08.
 * Time: 11:49
 */

namespace Managesieve\Exceptions;


/**
 * Class SocketException
 *
 * @author zdaniel
 * @package Managesieve\Exceptions
 */
class SocketException extends \RuntimeException
{

    /**
     * @var int
     */
    protected $code = 102;

    /**
     * @var string
     */
    private $details = '';

    /**
     * @param string $details
     */
    public function setDetails(string $details) {
        $this->details = $details;
    }

    /**
     * @return string
     */
    public function getDetails() : string {
        return $this->details;
    }

}