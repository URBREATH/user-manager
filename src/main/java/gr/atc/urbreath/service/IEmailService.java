package gr.atc.urbreath.service;

import org.springframework.mail.MailAuthenticationException;

import jakarta.mail.MessagingException;

public interface IEmailService {

    void sendMessage(String recipientAddress, String text, String subject, String fromUsername) throws MailAuthenticationException, MessagingException;

    void sendActivationLink(String username, String email, String activationToken);

    void sendResetPasswordLink(String username, String email, String resetToken);
}