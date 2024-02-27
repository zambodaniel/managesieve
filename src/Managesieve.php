<?php
/**
 * Created by PhpStorm.
 * User: zdaniel
 * Date: 2018.08.06.
 * Time: 16:03
 */

namespace Managesieve;

use Managesieve\Exceptions\AuthenticationException;
use Managesieve\Exceptions\SieveException;
use Managesieve\Exceptions\SocketException;
use Psr\Log\LoggerInterface;

/**
 * Class Managesieve
 *
 * @author zdaniel
 * @package Managesieve
 */
class Managesieve
{

    /**
     * Client is disconnected.
     */
    const STATE_DISCONNECTED = 1;

    /**
     * Client is connected but not authenticated.
     */
    const STATE_NON_AUTHENTICATED = 2;

    /**
     * Client is authenticated.
     */
    const STATE_AUTHENTICATED = 3;

    /**
     * Authentication with the best available method.
     */
    const AUTH_AUTOMATIC = 0;

    /**
     * DIGEST-MD5 authentication.
     */
    const AUTH_DIGESTMD5 = 'DIGEST-MD5';

    /**
     * CRAM-MD5 authentication.
     */
    const AUTH_CRAMMD5 = 'CRAM-MD5';

    /**
     * LOGIN authentication.
     */
    const AUTH_LOGIN = 'LOGIN';

    /**
     * PLAIN authentication.
     */
    const AUTH_PLAIN = 'PLAIN';

    /**
     * EXTERNAL authentication.
     */
    const AUTH_EXTERNAL = 'EXTERNAL';

    /**
     * The authentication methods this class supports.
     *
     * Can be overwritten if having problems with certain methods.
     *
     * @var array
     */
    public $supportedAuthMethods = array(
        self::AUTH_DIGESTMD5,
        self::AUTH_CRAMMD5,
        self::AUTH_EXTERNAL,
        self::AUTH_PLAIN,
        self::AUTH_LOGIN,
    );

    /**
     * SASL authentication methods that require Auth_SASL.
     *
     * @var array
     */
    public $supportedSASLAuthMethods = array(
        self::AUTH_DIGESTMD5,
        self::AUTH_CRAMMD5,
    );

    /**
     * The socket client.
     *
     * @var SocketClient
     */
    protected $sock;

    /**
     * Parameters and connection information.
     *
     * @var array
     */
    protected $params;

    /**
     * Current state of the connection.
     *
     * One of the STATE_* constants.
     *
     * @var integer
     */
    protected $state = self::STATE_DISCONNECTED;

    /**
     * Logging handler.
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Maximum number of referral loops
     *
     * @var array
     */
    protected $maxReferralCount = 15;

    protected $capability = [];

    /**
     * Constructor.
     *
     * If username and password are provided connects to the server and logs
     * in too.
     *
     * @param array $params  A hash of connection parameters:
     *   - host: Hostname of server (DEFAULT: localhost). Optionally prefixed
     *           with protocol scheme.
     *   - port: Port of server (DEFAULT: 4190).
     *   - user: Login username (optional).
     *   - password: Login password (optional).
     *   - authmethod: Type of login to perform (see $supportedAuthMethods)
     *                 (DEFAULT: AUTH_AUTOMATIC).
     *   - euser: Effective user. If authenticating as an administrator, login
     *            as this user.
     *   - bypassauth: Skip the authentication phase. Useful if passing an
     *                 already open socket.
     *   - secure: Security layer requested. One of:
     *     - true: (TLS if available/necessary) [DEFAULT]
     *     - false: (No encryption)
     *     - 'ssl': (Auto-detect SSL version)
     *     - 'sslv2': (Force SSL version 3)
     *     - 'sslv3': (Force SSL version 2)
     *     - 'tls': (TLS; started via protocol-level negotation over
     *              unencrypted channel)
     *     - 'tlsv1': (TLS version 1.x connection)
     *   - context: Additional options for stream_context_create().
     *   - logger: A log handler, must implement debug().
     *
     * @throws SieveException
     */
    public function __construct(string $host, string $user = '', string $password, int $port = null, LoggerInterface $logger = null)
    {
        $this->params = array_merge(
            array(
                'authmethod' => self::AUTH_AUTOMATIC,
                'bypassauth' => false,
                'context'    => array(),
                'euser'      => null,
                'host'       => 'localhost',
                'logger'     => null,
                'password'   => '',
                'port'       => 4190,
                'secure'     => true,
                'timeout'    => 5,
                'user'       => '',
            ),
            array(
                'user' => $user,
                'password' => $password,
                'host' => $host,
                'port' => $port ?? 4190,
                'logger' => $logger
            )
        );

        /* Try to include the Auth_SASL package.  If the package is not
         * available, we disable the authentication methods that depend upon
         * it. */
        if (!class_exists('Auth_SASL')) {
            $this->debug('Auth_SASL not present');
            $this->supportedAuthMethods = array_diff(
                $this->supportedAuthMethods,
                $this->supportedSASLAuthMethods
            );
        }

        if ($this->params['logger']) {
            $this->setLogger($this->params['logger']);
        }

        if (strlen($this->params['user']) &&
            strlen($this->params['password'])) {
            $this->handleConnectAndLogin();
        }
    }

    /**
     * Set user
     * @param string $user
     * @return $this
     */
    public function setUser(string $user) {
        $this->params['user'] = $user;
        return $this;
    }

    /**
     * Passes a logger for debug logging.
     *
     * @param object $logger   A log handler, must implement debug().
     */
    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    /**
     * Connects to the server and logs in.
     *
     * @throws SieveException
     */
    protected function handleConnectAndLogin()
    {
        $this->connect(
            $this->params['host'],
            $this->params['port'],
            $this->params['context'],
            $this->params['secure']
        );
        if (!$this->params['bypassauth']) {
            $this->login(
                $this->params['user'],
                $this->params['password'],
                $this->params['authmethod'],
                $this->params['euser']
            );
        }
    }

    /**
     * Handles connecting to the server and checks the response validity.
     *
     * Defaults from the constructor are used for missing parameters.
     *
     * @param string  $host    Hostname of server.
     * @param string  $port    Port of server.
     * @param array   $context List of options to pass to
     *                         stream_context_create().
     * @param boolean $secure Security layer requested. @see __construct().
     *
     * @throws SieveException
     */
    public function connect(
        $host = null, $port = null, $context = null, $secure = null
    )
    {
        if (isset($host)) {
            $this->params['host'] = $host;
        }
        if (isset($port)) {
            $this->params['port'] = $port;
        }
        if (isset($context)) {
            $this->params['context'] = array_merge_recursive(
                $this->params['context'],
                $context
            );
        }
        if (isset($secure)) {
            $this->params['secure'] = $secure;
        }

        if (self::STATE_DISCONNECTED != $this->state) {
            throw new SieveException();
        }

        try {
            $this->sock = new SocketClient(
                $this->params['host'],
                $this->params['port']
            );
        } catch (SocketException $e) {
            throw new SieveException($e);
        }

        if ($this->params['bypassauth']) {
            $this->state = self::STATE_AUTHENTICATED;
        } else {
            $this->state = self::STATE_NON_AUTHENTICATED;
            $this->doCmd();
        }

        // Explicitly ask for the capabilities in case the connection is
        // picked up from an existing connection.
        try {
            $this->cmdCapability();
        } catch (\Exception $e) {
            throw new SieveException($e);
        }

        // Check if we can enable TLS via STARTTLS.
        if ($this->params['secure'] === 'tls' ||
            ($this->params['secure'] === true &&
                !empty($this->capability['starttls']))) {
            $this->doCmd('STARTTLS');
            if (!$this->sock->startTls()) {
                throw new SieveException('Failed to establish TLS connection');
            }

            // The server should be sending a CAPABILITY response after
            // negotiating TLS. Read it, and ignore if it doesn't.
            // Unfortunately old Cyrus versions are broken and don't send a
            // CAPABILITY response, thus we would wait here forever. Parse the
            // Cyrus version and work around this broken behavior.
            if (!preg_match('/^CYRUS TIMSIEVED V([0-9.]+)/', $this->capability['implementation'], $matches) ||
                version_compare($matches[1], '2.3.10', '>=')) {
                $this->doCmd();
            }

            // Query the server capabilities again now that we are under
            // encryption.
            try {
                $this->cmdCapability();
            } catch (\Exception $e) {
                throw new SieveException($e);
            }
        }
    }

    /**
     * Disconnect from the Sieve server.
     *
     * @param boolean $sendLogoutCMD  Whether to send LOGOUT command before
     *                                disconnecting.
     *
     * @throws SieveException
     */
    public function disconnect($sendLogoutCMD = true)
    {
        $this->cmdLogout($sendLogoutCMD);
    }

    /**
     * Logs into server.
     *
     * Defaults from the constructor are used for missing parameters.
     *
     * @param string $user        Login username.
     * @param string $password    Login password.
     * @param string $authmethod  Type of login method to use.
     * @param string $euser       Effective UID (perform on behalf of $euser).
     *
     * @throws SieveException
     */
    public function login(
        $user = null, $password = null, $authmethod = null, $euser = null
    )
    {
        if (isset($user)) {
            $this->params['user'] = $user;
        }
        if (isset($password)) {
            $this->params['password'] = $password;
        }
        if (isset($authmethod)) {
            $this->params['authmethod'] = $authmethod;
        }
        if (isset($euser)) {
            $this->params['euser'] = $euser;
        }

        $this->checkConnected();
        if (self::STATE_AUTHENTICATED == $this->state) {
            throw new AuthenticationException('Already authenticated');
        }

        $this->cmdAuthenticate(
            $this->params['user'],
            $this->params['password'],
            $this->params['authmethod'],
            $this->params['euser']
        );
        $this->state = self::STATE_AUTHENTICATED;
    }

    /**
     * Returns an indexed array of scripts currently on the server.
     *
     * @return array  Indexed array of scriptnames.
     */
    public function listScripts()
    {
        if (is_array($scripts = $this->cmdListScripts())) {
            return $scripts[0];
        } else {
            return $scripts;
        }
    }

    /**
     * Returns the active script.
     *
     * @return string  The active scriptname.
     */
    public function getActive()
    {
        if (is_array($scripts = $this->cmdListScripts())) {
            return $scripts[1];
        }
        return '';
    }

    /**
     * Sets the active script.
     *
     * @param string $scriptname The name of the script to be set as active.
     *
     * @throws SieveException
     */
    public function setActive($scriptname)
    {
        $this->cmdSetActive($scriptname);
    }

    /**
     * Retrieves a script.
     *
     * @param string $scriptname The name of the script to be retrieved.
     *
     * @throws SieveException
     * @return string  The script.
     */
    public function getScript($scriptname)
    {
        return $this->cmdGetScript($scriptname);
    }

    /**
     * Adds a script to the server.
     *
     * @param string  $scriptname Name of the script.
     * @param string  $script     The script content.
     * @param boolean $makeactive Whether to make this the active script.
     *
     * @throws SieveException
     */
    public function installScript($scriptname, $script, $makeactive = false)
    {
        $this->cmdPutScript($scriptname, $script);
        if ($makeactive) {
            $this->cmdSetActive($scriptname);
        }
    }

    /**
     * Removes a script from the server.
     *
     * @param string $scriptname Name of the script.
     *
     * @throws SieveException
     */
    public function removeScript($scriptname)
    {
        $this->cmdDeleteScript($scriptname);
    }

    /**
     * Checks if the server has space to store the script by the server.
     *
     * @param string  $scriptname The name of the script to mark as active.
     * @param integer $size       The size of the script.
     *
     * @throws SieveException
     * @return boolean  True if there is space.
     */
    public function hasSpace($scriptname, $size)
    {
        $this->checkAuthenticated();

        try {
            $this->doCmd(
                sprintf('HAVESPACE %s %d', $this->escape($scriptname), $size)
            );
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Returns the list of extensions the server supports.
     *
     * @throws SieveException
     * @return array  List of extensions.
     */
    public function getExtensions()
    {
        $this->checkConnected();
        return $this->capability['extensions'];
    }

    /**
     * Returns whether the server supports an extension.
     *
     * @param string $extension The extension to check.
     *
     * @throws SieveException
     * @return boolean  Whether the extension is supported.
     */
    public function hasExtension($extension)
    {
        $this->checkConnected();

        $extension = trim(mb_strtoupper($extension));
        if (is_array($this->capability['extensions'])) {
            foreach ($this->capability['extensions'] as $ext) {
                if ($ext == $extension) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns the list of authentication methods the server supports.
     *
     * @throws SieveException
     * @return array  List of authentication methods.
     */
    public function getAuthMechs()
    {
        $this->checkConnected();
        return $this->capability['sasl'];
    }

    /**
     * Returns whether the server supports an authentication method.
     *
     * @param string $method The method to check.
     *
     * @throws SieveException
     * @return boolean  Whether the method is supported.
     */
    public function hasAuthMech($method)
    {
        $this->checkConnected();

        $method = trim(mb_strtoupper($method));
        if (is_array($this->capability['sasl'])) {
            foreach ($this->capability['sasl'] as $sasl) {
                if ($sasl == $method) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Handles the authentication using any known method.
     *
     * @param string $uid        The userid to authenticate as.
     * @param string $pwd        The password to authenticate with.
     * @param string $authmethod The method to use. If empty, the class chooses
     *                           the best (strongest) available method.
     * @param string $euser      The effective uid to authenticate as.
     *
     * @throws SieveException
     */
    protected function cmdAuthenticate(
        $uid, $pwd, $authmethod = null, $euser = ''
    )
    {
        $method = $this->getBestAuthMethod($authmethod);

        switch ($method) {
            case self::AUTH_DIGESTMD5:
                $this->_authDigestMD5($uid, $pwd, $euser);
                return;
            case self::AUTH_CRAMMD5:
                $this->_authCRAMMD5($uid, $pwd, $euser);
                break;
            case self::AUTH_LOGIN:
                $this->authLOGIN($uid, $pwd, $euser);
                break;
            case self::AUTH_PLAIN:
                $this->authPLAIN($uid, $pwd, $euser);
                break;
            case self::AUTH_EXTERNAL:
                $this->authEXTERNAL($uid, $pwd, $euser);
                break;
            default :
                throw new AuthenticationException(
                    $method . ' is not a supported authentication method'
                );
                break;
        }

        $this->doCmd();

        // Query the server capabilities again now that we are authenticated.
        try {
            $this->cmdCapability();
        } catch (\Throwable $e) {
            throw new SieveException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Authenticates the user using the PLAIN method.
     *
     * @param string $user  The userid to authenticate as.
     * @param string $pass  The password to authenticate with.
     * @param string $euser The effective uid to authenticate as.
     *
     * @throws SieveException
     * @return bool
     */
    protected function authPLAIN($user, $pass, $euser)
    {
        return $this->sendCmd(
            sprintf(
                'AUTHENTICATE "PLAIN" "%s"',
                base64_encode($euser . chr(0) . $user . chr(0) . $pass)
            )
        );
    }

    /**
     * Authenticates the user using the LOGIN method.
     *
     * @param string $user  The userid to authenticate as.
     * @param string $pass  The password to authenticate with.
     * @param string $euser The effective uid to authenticate as. Not used.
     *
     * @throws SieveException
     */
    protected function authLOGIN($user, $pass, $euser)
    {
        $this->sendCmd('AUTHENTICATE "LOGIN"');
        $this->doCmd('"' . base64_encode($user) . '"', true);
        $this->doCmd('"' . base64_encode($pass) . '"', true);
    }

    /**
     * Authenticates the user using the CRAM-MD5 method.
     *
     * @param string $user  The userid to authenticate as.
     * @param string $pass  The password to authenticate with.
     * @param string $euser The effective uid to authenticate as. Not used.
     *
     * @throws SieveException
     */
    protected function _authCRAMMD5($user, $pass, $euser)
    {
        $challenge = $this->doCmd('AUTHENTICATE "CRAM-MD5"', true);
        $challenge = base64_decode(trim($challenge));
        $cram = Auth_SASL::factory('crammd5');
        $response = $cram->getResponse($user, $pass, $challenge);
        if (is_a($response, 'PEAR_Error')) {
            throw new SieveException($response);
        }
        $this->sendStringResponse(base64_encode($response));
    }

    /**
     * Authenticates the user using the DIGEST-MD5 method.
     *
     * @param string $user  The userid to authenticate as.
     * @param string $pass  The password to authenticate with.
     * @param string $euser The effective uid to authenticate as.
     *
     * @throws SieveException
     */
    protected function _authDigestMD5($user, $pass, $euser)
    {
        $challenge = $this->doCmd('AUTHENTICATE "DIGEST-MD5"', true);
        $challenge = base64_decode(trim($challenge));
        $digest = Auth_SASL::factory('digestmd5');
        // @todo Really 'localhost'?
        $response = $digest->getResponse(
            $user, $pass, $challenge, 'localhost', 'sieve', $euser
        );
        if (is_a($response, 'PEAR_Error')) {
            throw new SieveException($response);
        }

        $this->sendStringResponse(base64_encode($response));
        $this->doCmd('', true);
        if (mb_strtoupper(substr($response, 0, 2)) == 'OK') {
            return;
        }

        /* We don't use the protocol's third step because SIEVE doesn't allow
         * subsequent authentication, so we just silently ignore it. */
        $this->sendStringResponse('');
        $this->doCmd();
    }

    /**
     * Authenticates the user using the EXTERNAL method.
     *
     * @param string $user  The userid to authenticate as.
     * @param string $pass  The password to authenticate with.
     * @param string $euser The effective uid to authenticate as.
     *
     * @throws SieveException
     * @return bool
     */
    protected function authEXTERNAL($user, $pass, $euser)
    {
        $cmd = sprintf(
            'AUTHENTICATE "EXTERNAL" "%s"',
            base64_encode(strlen($euser) ? $euser : $user)
        );
        return $this->sendCmd($cmd);
    }

    /**
     * Removes a script from the server.
     *
     * @param string $scriptname Name of the script to delete.
     *
     * @throws SieveException
     */
    protected function cmdDeleteScript($scriptname)
    {
        $this->checkAuthenticated();
        $this->doCmd(sprintf('DELETESCRIPT %s', $this->escape($scriptname)));
    }

    /**
     * Retrieves the contents of the named script.
     *
     * @param string $scriptname Name of the script to retrieve.
     *
     * @throws SieveException
     * @return string  The script.
     */
    protected function cmdGetScript($scriptname)
    {
        $this->checkAuthenticated();
        $result = $this->doCmd(
            sprintf('GETSCRIPT %s', $this->escape($scriptname))
        );
        return preg_replace('/^{[0-9]+}\r\n/', '', $result);
    }

    /**
     * Sets the active script, i.e. the one that gets run on new mail by the
     * server.
     *
     * @param string $scriptname The name of the script to mark as active.
     *
     * @throws SieveException
     */
    protected function cmdSetActive($scriptname)
    {
        $this->checkAuthenticated();
        $this->doCmd(sprintf('SETACTIVE %s', $this->escape($scriptname)));
    }

    /**
     * Returns the list of scripts on the server.
     *
     * @throws SieveException
     * @return array  An array with the list of scripts in the first element
     *                and the active script in the second element.
     */
    protected function cmdListScripts()
    {
        $this->checkAuthenticated();

        $result = $this->doCmd('LISTSCRIPTS');

        $scripts = array();
        $activeScript = null;
        $result = explode("\r\n", $result);
        foreach ($result as $value) {
            if (preg_match('/^"(.*)"( ACTIVE)?$/i', $value, $matches)) {
                $script_name = stripslashes($matches[1]);
                $scripts[] = $script_name;
                if (!empty($matches[2])) {
                    $activeScript = $script_name;
                }
            }
        }

        return array($scripts, $activeScript);
    }

    /**
     * Adds a script to the server.
     *
     * @param string $scriptname Name of the new script.
     * @param string $scriptdata The new script.
     *
     * @throws SieveException
     */
    protected function cmdPutScript($scriptname, $scriptdata)
    {
        $this->checkAuthenticated();
        $command = sprintf(
            "PUTSCRIPT %s {%d+}\r\n%s",
            $this->escape($scriptname),
            strlen($scriptdata),
            $scriptdata
        );
        $this->doCmd($command);
    }

    /**
     * Logs out of the server and terminates the connection.
     *
     * @param boolean $sendLogoutCMD Whether to send LOGOUT command before
     *                               disconnecting.
     *
     * @throws SieveException
     */
    protected function cmdLogout($sendLogoutCMD = true)
    {
        $this->checkConnected();
        if ($sendLogoutCMD) {
            $this->doCmd('LOGOUT');
        }
        $this->sock->close();
        $this->state = self::STATE_DISCONNECTED;
    }

    /**
     * Sends the CAPABILITY command
     *
     * @throws SieveException
     */
    protected function cmdCapability()
    {
        $this->checkConnected();
        $result = $this->doCmd('CAPABILITY');
        $this->parseCapability($result);
    }

    /**
     * Parses the response from the CAPABILITY command and stores the result
     * in $capability.
     *
     * @param string $data The response from the capability command.
     */
    protected function parseCapability($data)
    {
        // Clear the cached capabilities.
        $this->capability = array(
            'sasl' => array(),
            'extensions' => array()
        );

        $data = preg_split(
            '/\r?\n/',
            mb_strtoupper($data),
            -1,
            PREG_SPLIT_NO_EMPTY
        );

        for ($i = 0; $i < count($data); $i++) {
            if (!preg_match('/^"([A-Z]+)"( "(.*)")?$/', $data[$i], $matches)) {
                continue;
            }
            switch ($matches[1]) {
                case 'IMPLEMENTATION':
                    $this->capability['implementation'] = $matches[3];
                    break;

                case 'SASL':
                    $this->capability['sasl'] = preg_split('/\s+/', $matches[3]);
                    break;

                case 'SIEVE':
                    $this->capability['extensions'] = preg_split('/\s+/', $matches[3]);
                    break;

                case 'STARTTLS':
                    $this->capability['starttls'] = true;
                    break;
            }
        }
    }

    /**
     * Sends a command to the server
     *
     * @param string $cmd The command to send.
     * @return bool
     */
    protected function sendCmd($cmd)
    {
        $status = $this->sock->getStatus();
        if ($status['eof']) {
            throw new SieveException('Failed to write to socket: connection lost');
        }
        $this->sock->write($cmd . "\r\n");
        $this->debug("C: $cmd");
        return true;
    }

    /**
     * Sends a string response to the server.
     *
     * @param string $str The string to send.
     * @return bool
     */
    protected function sendStringResponse($str)
    {
        return $this->sendCmd('{' . strlen($str) . "+}\r\n" . $str);
    }

    /**
     * Receives a single line from the server.
     *
     * @return string  The server response line.
     */
    protected function recvLn()
    {
        $lastline = rtrim($this->sock->gets(8192));
        $this->debug("S: $lastline");
        if ($lastline === '') {
            throw new SieveException('Failed to read from socket');
        }
        return $lastline;
    }

    /**
     * Receives a number of bytes from the server.
     *
     * @param integer $length  Number of bytes to read.
     *
     * @return string  The server response.
     */
    protected function recvBytes($length)
    {
        $response = '';
        $response_length = 0;
        while ($response_length < $length) {
            $response .= $this->sock->read($length - $response_length);
            $response_length = strlen($response);
        }
        $this->debug('S: ' . rtrim($response));
        return $response;
    }

    /**
     * Send a command and retrieves a response from the server.
     *
     * @param string $cmd   The command to send.
     * @param boolean $auth Whether this is an authentication command.
     *
     * @throws SieveException if a NO response.
     * @return string  Reponse string if an OK response.
     *
     */
    protected function doCmd($cmd = '', $auth = false)
    {
        $referralCount = 0;
        while ($referralCount < $this->maxReferralCount) {
            if (strlen($cmd)) {
                $this->sendCmd($cmd);
            }

            $response = '';
            while (true) {
                $line = $this->recvLn();

                if (preg_match('/^(OK|NO)/i', $line, $tag)) {
                    // Check for string literal message.
                    // DBMail has some broken versions that send the trailing
                    // plus even though it's disallowed.
                    if (preg_match('/{([0-9]+)\+?}$/', $line, $matches)) {
                        $line = substr($line, 0, -(strlen($matches[1]) + 2))
                            . str_replace(
                                "\r\n", ' ', $this->recvBytes($matches[1] + 2)
                            );
                    }

                    if ('OK' == mb_strtoupper($tag[1])) {
                        $response .= $line;
                        return rtrim($response);
                    }

                    throw new SieveException(trim($response . substr($line, 2)), 3);
                }

                if (preg_match('/^BYE/i', $line)) {
                    try {
                        $this->disconnect(false);
                    } catch (\Exception $e) {
                        throw new SieveException(
                            'Cannot handle BYE, the error was: '
                            . $e->getMessage(),
                            4
                        );
                    }
                    // Check for referral, then follow it.  Otherwise, carp an
                    // error.
                    if (preg_match('/^bye \(referral "(sieve:\/\/)?([^"]+)/i', $line, $matches)) {
                        // Replace the old host with the referral host
                        // preserving any protocol prefix.
                        $this->params['host'] = preg_replace(
                            '/\w+(?!(\w|\:\/\/)).*/', $matches[2],
                            $this->params['host']
                        );
                        try {
                            $this->handleConnectAndLogin();
                        } catch (\Exception $e) {
                            throw new SieveException(
                                'Cannot follow referral to '
                                . $this->params['host'] . ', the error was: '
                                . $e->getMessage()
                            );
                        }
                        break;
                    }
                    throw new SieveException(trim($response . $line), 6);
                }

                if (preg_match('/^{([0-9]+)}/', $line, $matches)) {
                    // Matches literal string responses.
                    $line = $this->recvBytes($matches[1] + 2);
                    if (!$auth) {
                        // Receive the pending OK only if we aren't
                        // authenticating since string responses during
                        // authentication don't need an OK.
                        $this->recvLn();
                    }
                    return $line;
                }

                if ($auth) {
                    // String responses during authentication don't need an
                    // OK.
                    $response .= $line;
                    return rtrim($response);
                }

                $response .= $line . "\r\n";
                $referralCount++;
            }
        }

        throw new SieveException('Max referral count (' . $referralCount . ') reached.');
    }

    /**
     * Returns the name of the best authentication method that the server
     * has advertised.
     *
     * @param string $authmethod Only consider this method as available.
     *
     * @throws SieveException
     * @return string  The name of the best supported authentication method.
     */
    protected function getBestAuthMethod($authmethod = null)
    {
        if (!isset($this->capability['sasl'])) {
            throw new AuthenticationException(
                'This server doesn\'t support any authentication methods. SASL problem?'
            );
        }
        if (!$this->capability['sasl']) {
            throw new AuthenticationException(
                'This server doesn\'t support any authentication methods.'
            );
        }

        if ($authmethod) {
            if (in_array($authmethod, $this->capability['sasl'])) {
                return $authmethod;
            }
            throw new AuthenticationException(
                sprintf(
                    'No supported authentication method found. The server supports these methods: %s, but we want to use: %s',
                    implode(', ', $this->capability['sasl']),
                    $authmethod
                )
            );
        }

        foreach ($this->supportedAuthMethods as $method) {
            if (in_array($method, $this->capability['sasl'])) {
                return $method;
            }
        }

        throw new AuthenticationException(
            sprintf(
                'No supported authentication method found. The server supports these methods: %s, but we only support: %s',
                implode(', ', $this->capability['sasl']),
                implode(', ', $this->supportedAuthMethods)
            )
        );
    }

    /**
     * Asserts that the client is in disconnected state.
     *
     * @throws SieveException
     */
    protected function checkConnected()
    {
        if (self::STATE_DISCONNECTED == $this->state) {
            throw new SieveException();
        }
    }

    /**
     * Asserts that the client is in authenticated state.
     *
     * @throws SieveException
     */
    protected function checkAuthenticated()
    {
        if (self::STATE_AUTHENTICATED != $this->state) {
            throw new SieveException();
        }
    }

    /**
     * Converts strings into RFC's quoted-string or literal-c2s form.
     *
     * @param string $string  The string to convert.
     *
     * @return string  Result string.
     */
    protected function escape($string)
    {
        // Some implementations don't allow UTF-8 characters in quoted-string,
        // use literal-c2s.
        if (preg_match('/[^\x01-\x09\x0B-\x0C\x0E-\x7F]/', $string)) {
            return sprintf("{%d+}\r\n%s", strlen($string), $string);
        }

        return '"' . addcslashes($string, '\\"') . '"';
    }

    /**
     * Write debug text to the current log handler.
     *
     * @param string $message  Debug message text.
     */
    protected function debug($message)
    {
        if ($this->logger) {
            $this->logger->debug($message);
        }
    }
}