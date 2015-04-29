<?php

namespace Simplement\Security;

use Nette\Security\IUserStorage,
    Nette\Security\IAuthenticator,
    Nette\Security\IAuthorizator;

/**
 * Description of User
 *
 * @author Martin Dendis <martin.dendis@improvisio.cz>
 *
 * @property-read Authenticator $authenticator
 * @property-read Verificator $verificator
 */
class User extends \Nette\Security\User {

    /** @var Verificator */
    private $verificator;

    public function __construct(IUserStorage $storage, IAuthenticator $authenticator, IAuthorizator $authorizator = NULL, Verificator $verificator = NULL) {
        parent::__construct($storage, $authenticator, $authorizator);
        $this->verificator = $verificator;

        if ($this->authenticator instanceof Authenticator) {
            if (!$this->isLoggedIn()) {
                $authenticator->tryAuthenticateByCookies($this);
            }
        }
    }

    /**
     * Logs out the user from the current session.
     *
     * Deletes the user's logon token for a permanent login.
     *
     * @param  bool  clear the identity from persistent storage?
     * @return void
     */
    public function logout($clearIdentity = FALSE) {
        if ($this->authenticator instanceof Authenticator) {
            $this->authenticator->forgetMe($this);
        }

        parent::logout($clearIdentity);
    }

    /**
     *
     * @return Verificator
     */
    public function getVerificator() {
        return $this->verificator;
    }

}
