<?php
/**
 * Created by PhpStorm.
 * User: zdaniel
 * Date: 2018.08.08.
 * Time: 11:46
 */

namespace Managesieve;


use Managesieve\Exceptions\SocketException;

/**
 * Class SocketClient
 *
 * @author zdaniel
 * @package Managesieve
 */
class SocketClient
{
    /**
     * Is there an active connection?
     *
     * @var boolean
     */
    protected $connected = false;

    /**
     * Configuration parameters.
     *
     * @var array
     */
    protected $params = [];

    /**
     * Is the connection secure?
     *
     * @var boolean
     */
    protected $secure = false;

    /**
     * The actual socket.
     *
     * @var resource
     */
    protected $stream = null;

    /**
     * Constructor.
     *
     * @param string $host      Hostname of remote server (can contain
     *                          protocol prefx).
     * @param integer $port     Port number of remote server.
     * @param integer $timeout  Connection timeout (in seconds).
     * @param mixed $secure     Security layer requested. One of:
     *   - false: (No encryption) [DEFAULT]
     *   - 'ssl': (Auto-detect SSL version)
     *   - 'sslv2': (Force SSL version 3)
     *   - 'sslv3': (Force SSL version 2)
     *   - 'tls': (TLS; started via protocol-level negotation over unencrypted
     *     channel)
     *   - 'tlsv1': (TLS version 1.x connection)
     *   - true: (TLS if available/necessary)
     * @param array $context    Any context parameters passed to
     *                          stream_create_context().
     * @param array $params     Additional options.
     *
     * @throws SocketException
     */
    public function __construct(
        string $host, int $port = null, int $timeout = 30, $secure = false,
        array $context = [], array $params = []
    )
    {
        if ($secure && !extension_loaded('openssl')) {
            if ($secure !== true) {
                throw new SocketException('Secure connections require the PHP openssl extension.');
            }
            $secure = false;
        }

        $context = array_merge_recursive(
            [
                'ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false
                ]
            ],
            $context
        );

        $this->params = $params;

        $this->connect($host, $port, $timeout, $secure, $context);
    }

    /**
     * @param $name
     * @return bool
     */
    public function __get($name)
    {
        switch ($name) {
            case 'connected':
                return $this->connected;

            case 'secure':
                return $this->secure;
        }
    }

    /**
     * This object can not be cloned.
     */
    public function __clone()
    {
        throw new SocketException('Object cannot be cloned.');
    }

    /**
     * This object can not be serialized.
     */
    public function __sleep()
    {
        throw new SocketException('Object can not be serialized.');
    }

    /**
     * Start a TLS connection.
     *
     * @return boolean  Whether TLS was successfully started.
     */
    public function startTls()
    {
        if ($this->connected && !$this->secure) {
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT')) {
                $mode = STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT
                    | STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT
                    | STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            } else {
                $mode = STREAM_CRYPTO_METHOD_TLS_CLIENT;
            }
            if (stream_socket_enable_crypto($this->stream, true, $mode) === true) {
                $this->secure = true;
                return true;
            }
        }

        return false;
    }

    /**
     * Close the connection.
     * @return $this
     */
    public function close()
    {
        if ($this->connected) {
            fclose($this->stream);
            $this->connected = $this->secure = false;
            $this->stream = null;
        }
        return $this;
    }

    /**
     * Returns information about the connection.
     *
     * Currently returns four entries in the result array:
     *  - timed_out (bool): The socket timed out waiting for data
     *  - blocked (bool): The socket was blocked
     *  - eof (bool): Indicates EOF event
     *  - unread_bytes (int): Number of bytes left in the socket buffer
     *
     * @throws SocketException
     * @return array  Information about existing socket resource.
     */
    public function getStatus() : array
    {
        $this->checkStream();
        $res = stream_get_meta_data($this->stream);
        if ($res === false) {
            throw new SocketException('Error reading metadata from socket');
        }
        return $res;
    }

    /**
     * Returns a line of data.
     *
     * @param int $size  Reading ends when $size - 1 bytes have been read,
     *                   or a newline or an EOF (whichever comes first).
     *
     * @throws SocketException
     * @return string  $size bytes of data from the socket
     */
    public function gets($size) : string
    {
        $this->checkStream();
        $data = fgets($this->stream, $size);
        if ($data === false) {
            throw new SocketException('Error reading data from socket');
        }
        return $data;
    }

    /**
     * Returns a specified amount of data.
     *
     * @param integer $size  The number of bytes to read from the socket.
     *
     * @throws SocketException
     * @return string  $size bytes of data from the socket.
     */
    public function read($size) : string
    {
        $this->checkStream();
        $data = fread($this->stream, $size);
        if ($data === false) {
            throw new SocketException('Error reading data from socket');
        }
        return $data;
    }

    /**
     * Writes data to the stream.
     *
     * @param string $data  Data to write.
     *
     * @throws SocketException
     */
    public function write(string $data)
    {
        $this->checkStream();
        if (!fwrite($this->stream, $data)) {
            $meta_data = $this->getStatus();
            if (!empty($meta_data['timed_out'])) {
                throw new SocketException('Timed out writing data to socket');
            }
            throw new SocketException('Error writing data to socket');
        }
    }

    /**
     * Connect to the remote server.
     * @param $host
     * @param $port
     * @param $timeout
     * @param $secure
     * @param $context
     * @param int $retries
     */
    protected function connect(
        $host, $port, $timeout, $secure, $context, $retries = 0
    )
    {
        $conn = '';
        if (!strpos($host, '://')) {
            switch (strval($secure)) {
                case 'ssl':
                case 'sslv2':
                case 'sslv3':
                    $conn = $secure . '://';
                    $this->secure = true;
                    break;

                case 'tlsv1':
                    $conn = 'tls://';
                    $this->secure = true;
                    break;

                case 'tls':
                default:
                    $conn = 'tcp://';
                    break;
            }
        }
        $conn .= $host;
        if ($port) {
            $conn .= ':' . $port;
        }

        $this->stream = stream_socket_client(
            $conn,
            $error_number,
            $error_string,
            $timeout,
            STREAM_CLIENT_CONNECT,
            stream_context_create($context)
        );

        if ($this->stream === false) {
            /* From stream_socket_client() page: a function return of false,
             * with an error code of 0, indicates a "problem initializing the
             * socket". These kind of issues are seen on the same server
             * (and even the same user account) as sucessful connections, so
             * these are likely transient issues. Retry up to 3 times in these
             * instances. */
            if (!$error_number && ($retries < 3)) {
                $this->connect($host, $port, $timeout, $secure, $context, ++$retries);
            }

            $e = new SocketException('Error connecting to server.');
            $e->setDetails(sprintf("[%u] %s", $error_number, $error_string));
            throw $e;
        }

        stream_set_timeout($this->stream, $timeout);
        stream_set_read_buffer($this->stream, 0);
        stream_set_write_buffer($this->stream, 0);

        $this->connected = true;
    }

    /**
     * Throws an exception is the stream is not a resource.
     *
     * @throws SocketException
     */
    protected function checkStream()
    {
        if (!is_resource($this->stream)) {
            throw new SocketException('Not connected');
        }
    }

}