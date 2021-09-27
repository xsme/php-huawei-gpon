<?php

/**
 * @author Sebastian Rzeszutek <sebastian.rzeszutek@itmotion.pl>
 * @copyright 2021 Sebastian Rzeszutek
 */

namespace xsme\HuaweiGpon;

use Exception;
use phpseclib3\Net\SSH2;

class Terminal
{
    /**
     * Konstruktor
     *
     * @param string $ipAddress adres ip do mngt urzadznia
     * @param string $login login uzytkownika SSH
     * @param string $password haslo uzytwkonika SSH
     * @param int $port port do polaczaenia ssh, domyslnie 22
     * @param int $timeout timeout dla polaczenia SSH, wylaczamy podajac false lub 0 
     * @param string $socksIp adres serwera SOCKS jezeli uzywamy proxy do polaczania SSH
     * @param int $socksPort port serwera SOCKS jezeli uzywamy proxy do polaczania SSH
     * @return Terminal
     */
    public function __construct(string $ipAddress, string $login, string $password, int $port = 22, int $timeOut = 3, string $socksIp = null, int $socksPort = null) : Terminal
    {
        $this->login = $login;
        $this->password = $password;
        $this->connection = (ip2long($socksIp) !== false)
            ? new SSH2($this->socksConnection($ipAddress, $port, $socksIp, $socksPort))
            : new SSH2($ipAddress, $port);
        $this->connection->setTimeout($timeOut);
        if (!$this->connection->login($login, $password)) {
            exit('Login failed!');
        }
        return $this;
    }

    /**
     * Inicjowanie połączenia przez SOCKS5
     *
     * @param string $ipAddress adres urzadzenia OLT
     * @param int $port port do polaczenia SSH do OLT
     * @param string $socksIp adres serwera proxy SOCKS
     * @param int $socksPort port serwera proxy SOCKS
     * @return mixed
     */
    private function socksConnection(string $ipAddress, int $port, string $socksIp, int $socksPort)
    {
        $fsock = fsockopen($socksIp, $socksPort, $errNo, $errStr, 1);
        if (!$fsock) {
            throw new Exception($errStr);
        }
        $port = pack('n', $port);
        $address = chr(strlen($ipAddress)) . $ipAddress;
        $request = "\5\1\0";
        if (fwrite($fsock, $request) != strlen($request)) {
            throw new \Exception('Premature termination');
        }

        $response = fread($fsock, 2);
        if ($response != "\5\0") {
            throw new \Exception('Unsupported protocol or unsupported method');
        }

        $request = "\5\1\0\3$address$port";
        if (fwrite($fsock, $request) != strlen($request)) {
            throw new \Exception('Premature termination');
        }

        $response = fread($fsock, strlen($address) + 6);
        if (substr($response, 0, 2) != "\5\0") {
        echo bin2hex($response) . "\n";
            throw new \Exception("Unsupported protocol or connection refused");
        }
        return $fsock;
    }

    /**
     * Wysyłanie komendy RAW do terminala.
     * Jezeli jest włączony debug, to komenda nie 
     * zostanie wysłana, będzie wyświetlona jako
     * output wywołanej funkcji.
     *
     * @param string $command komenda do wpisania w wiersz poleceń
     * @return Terminal
     */
    public function send($command = ''): Terminal
    {
        $this->connection->write($command);
        return $this;
    }

    /**
     * Odczytywanie informacji z terminala.
     * Jezeli jest włączony debug, to komenda nie 
     * zostanie wysłana, będzie wyświetlona 
     * informacja o wywołanej funkcji.
     *
     * @return string
     */
    public function read(): string
    {
        return $this->connection->read();
    }
}