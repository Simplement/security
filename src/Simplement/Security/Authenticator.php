<?php

namespace Simplement\Security;

use Nette\Http\IRequest,
	Nette\Http\IResponse,
	Nette\Security\Identity,
	App\Model\Database\Entity,
	Kdyby\Doctrine\EntityManager;

/**
 * Description of Authenticator
 *
 * @author Martin Dendis <martin.dendis@improvisio.cz>
 */
class Authenticator extends \Nette\Object implements \Nette\Security\IAuthenticator {

	// 6 * 30 * 24 * 60 * 60
	const REMEMBER_TIME = 15552000;
	const IDENTITY_LOG = 'user_log_logging';
	const COOKIE_PERNAMENT = 'Security_Authentificator_Pernament';

	/** @var EntityManager */
	private $em;

	/** @var IRequest */
	public $httpRequest;

	/** @var IResponse */
	public $httpResponse;

	public function __construct(EntityManager $em, IRequest $request, IResponse $response) {
		$this->em = $em;
		$this->httpRequest = $request;
		$this->httpResponse = $response;
	}

	public function tryAuthenticateByCookies(User $user) {
		if (!($hash = $this->httpRequest->getCookie(self::COOKIE_PERNAMENT)) || $user->isLoggedIn()) {
			return;
		}

		$query = $this->em->createQuery('SELECT l'
			. ' FROM ' . Entity\LogLogging::cls() . ' l'
			. ' LEFT JOIN l.user u'
			. ' WHERE l.rememberHash = :hash'
			. ' AND (:httpAgent IS NULL OR l.httpUserAgent = :httpAgent)'
			. ' AND l.validTill > :now'
			. ' AND u.deletedAt IS NULL'
		);

		$query->setParameters(array(
			'hash' => $hash,
			'httpAgent' => (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : NULL),
			'now' => new \DateTime,
		));

		if (!($result = $query->getResult())) {
			$this->forgetMe($user);
			return;
		}

		$log = reset($result);
		$log->rememberHash = NULL;
		$log->validTill = NULL;

		$this->em->persist($log);

		$user->login($this->createIdentity($log->user));

		$this->rememberMe($user);
	}

	public function rememberMe(User $user) {
		if (!$user->isLoggedIn()) {
			return;
		}

		$this->forgetMe($user);

		$validTill = time() + self::REMEMBER_TIME;

		$hash = time() . '$' . md5(json_encode($user->identity->data));

		do {
			$query = $this->em->createQuery('SELECT l'
				. ' FROM ' . Entity\LogLogging::cls() . ' l'
				. ' LEFT JOIN l.user u'
				. ' WHERE l.rememberHash = :hash'
				. ' AND l.validTill > :now'
				. ' AND u.deletedAt IS NULL');

			$query->setParameters(array(
				'hash' => ($randomHash = $hash . rand(1000000000, 9999999999)),
				'now' => new \DateTime,
			));
		} while ($query->getResult());

		$query = $this->em->createQuery('SELECT l'
			. ' FROM ' . Entity\LogLogging::cls() . ' l'
			. ' WHERE l.id = :id');
		$query->setParameter('id', $user->identity->data[self::IDENTITY_LOG]);

		if (!($result = $query->getResult())) {
			return;
		}

		$log = reset($result);
		$log->rememberHash = $randomHash;
		$log->validTill = \Nette\Utils\DateTime::from($validTill);

		$this->em->persist($log)->flush();

		$this->httpResponse->setCookie(self::COOKIE_PERNAMENT, $randomHash, $validTill);
	}

	public function forgetMe(User $user) {
		$this->httpResponse->setCookie(self::COOKIE_PERNAMENT, NULL, 0);

		if (!$user->isLoggedIn()) {
			return;
		}

		$query = $this->em->createQuery('SELECT l'
			. ' FROM ' . Entity\LogLogging::cls() . ' l'
			. ' WHERE l.id = :id');
		$query->setParameter('id', $user->identity->data[self::IDENTITY_LOG]);

		if (!($result = $query->getResult())) {
			return;
		}

		$log = reset($result);
		$log->rememberHash = NULL;
		$log->validTill = NULL;

		$this->em->persist($log)->flush();
	}

	public function authenticate(array $credentials) {
		list($email, $password) = $credentials;

		$query = $this->em->createQuery('SELECT u'
			. ' FROM ' . Entity\User::cls() . ' u'
			. ' WHERE u.email = :email'
			. ' AND u.deletedAt IS NULL');
		$query->setParameter('email', $email);

		$result = $query->getResult();

		if (!$result) {
			throw new \Nette\Security\AuthenticationException;
		}

		$user = reset($result);

		if (!\Nette\Security\Passwords::verify($password, $user->password)) {
			throw new \Nette\Security\AuthenticationException;
		} elseif (\Nette\Security\Passwords::needsRehash($user->password)) {
			$user->password = \Nette\Security\Passwords::hash($password);
			$this->em->persist($user);
		}

		return $this->createIdentity($user);
	}

	protected function createIdentity(Entity\User $user) {
		$log = new Entity\LogLogging($user);
		$log->remoteAddr = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : NULL;
		$log->httpXForwardedFor = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : NULL;
		$log->httpUserAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : NULL;

		$this->em->persist($log)->flush();

		$arr = $user->toArray();
		unset($arr['password']);

		$arr[self::IDENTITY_LOG] = $log->id;

		return new Identity($user->id, $user->role, $arr);
	}

	public function createUser($email, $password, $firstName, $lastName, $phone) {
		$user = new Entity\User($email, \Nette\Security\Passwords::hash($password), $firstName, $lastName, $phone, Entity\User::ROLE_CUSTOMER);

		$result = $this->em->createQuery('SELECT u'
				. ' FROM ' . Entity\User::cls() . ' u'
				. ' WHERE u.email = :email')
			->setParameter('email', $user->email)
			->getResult();

		if ($result) {
			throw new \Nette\Security\AuthenticationException;
		}

		$this->em->persist($user)->flush();
	}

}
