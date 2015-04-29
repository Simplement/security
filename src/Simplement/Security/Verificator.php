<?php

namespace Simplement\Security;

use App\Model\Database\Entity,
    Kdyby\Doctrine\EntityManager,
    Simplement\Mail\TemplateFactory,
    Nette\Localization\ITranslator;

/**
 * Description of Verificator
 *
 * @author Martin Dendis <martin.dendis@improvisio.cz>
 */
class Verificator extends \Nette\Object {

    /** Verification level */
    const EMAIL = 1;

    /** @var TemplateFactory */
    private $templateFactory;

    /** @var EntityManager */
    private $em;

    /** @var array */
    private $setting;

    /** @var ITranslator */
    private $translator;

    public function __construct(array $setting, EntityManager $em, TemplateFactory $templateFactory) {
        $this->templateFactory = $templateFactory;
        $this->em = $em;
        $this->translator = new \Simplement\Localization\DummyTranslator;

        $this->setting = array(
            'minimalVerification' => self::EMAIL,
            'verificationEmail' => NULL,
            'verificationEmailName' => NULL,
            'verificationEmailSubject' => 'Ověření emailové adresy',
            'verificationEmailTemplate' => \Nette\Environment::getVariable('appDir') . '/templates/emails/verificateEmail.latte',
        );

        $this->setting = $setting + $this->setting;
    }

    public function isVerifed($id) {
        return $this->hasVerifed($id, $this->setting['minimalVerification']);
    }

    public function hasVerifedEmail($id) {
        return $this->hasVerifed($id, self::EMAIL);
    }

    public function hasVerifed($id, $what = NULL) {
        $what || $what = $this->setting['minimalVerification'];
        return $this->verife($id, $what);
    }

    public function verifeEmail($id, $hash) {
        return $this->verife($id, self::EMAIL, 'emailVerificationHash', $hash);
    }

    private function verife($id, $what, $column = NULL, $hash = NULL) {
        if (($ret = $this->tryResolveByRole($id)) !== NULL) {
            return $ret;
        }

        $user = $this->getRecord($id);

        if (($user->verifed & $what) === $what) {
            return TRUE;
        }

        if ($column && $hash) {
            if ($user->$column === $hash) {
                $user->verifed = $user->verifed | $what;
                $user->$column = NULL;
                $this->em->persist($user)->flush();
                return TRUE;
            }
        }

        return FALSE;
    }

    public function sendEmailVerification($id) {
        if (($ret = $this->tryResolveByRole($id)) !== NULL) {
            return $ret;
        }
        if ($this->hasVerifedEmail($id)) {
            return FALSE;
        }

        $user = $this->getRecord($id);

        $template = $this->templateFactory->createTemplate($this->setting['verificationEmailTemplate']);
        $template->setTranslator($this->translator);

        $user->emailVerificationHash = $template->hash = time() . '$' . md5(rand(1000000000, 9999999999));
        $this->em->persist($user)->flush();

        $template->id = $id;
        $template->firstName = $user->firstName;
        $template->lastName = $user->lastName;

        $mail = new \Nette\Mail\Message;
        $mail->addTo($user->email, $user->firstName . ' ' . $user->lastName);
        $this->setting['verificationEmailSubject'] && $mail->setSubject($this->translator->translate($this->setting['verificationEmailSubject']));
        $this->setting['verificationEmail'] && $mail->setFrom($this->setting['verificationEmail'], $this->setting['verificationEmailName']);
        $mail->setHtmlBody($template);

        $this->templateFactory->sendMail($mail);
    }

    private function tryResolveByRole($id) {
        if (!($user = $this->getRecord($id))) {
            return FALSE;
        }

        switch ($user->role) {
            case Entity\User::ROLE_ADMIN:
                return TRUE;
            case 'guest':
                return FALSE;
        }
    }

    /**
     *
     * @param integer $id
     * @return Entity\User
     */
    private function getRecord($id) {
        return $this->em->find(Entity\User::cls(), $id);
    }

}
