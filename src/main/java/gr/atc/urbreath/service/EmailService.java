package gr.atc.urbreath.service;

import java.util.concurrent.CompletableFuture;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class EmailService implements IEmailService {

  private final JavaMailSender javaMailSender;

  @Value("${spring.mail.username}")
  private String mailUsername;

  @Value("${app.frontend.url}")
  private String frontendUrl;

  private static final String SUBJECT_ACTIVATE_STRING = "Welcome to UrBreath! Activate your account";
  private static final String SUBJECT_RESET_STRING = "Reset your password in UrBreath";
  private static final String ACTIVATE_ACCOUNT_EMAIL_TEMPLATE = """
             <!DOCTYPE html>
                        <html>
                        <head>
                          <meta charset="UTF-8">
                          <meta name="viewport" content="width=device-width, initial-scale=1.0">
                          <title>Account Activation</title>
                        </head>
                        <body style="font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; line-height: 1.5;">
                          <div style="max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);">
                            <p style="font-size: 16px;">Hello %s,</p>
             
                            <p style="font-size: 16px;">An account has been created for you in UrBreath. Click the button below to activate your account and set up your password.</p>
             
                             <div style="text-align: center; margin: 40px 0;">
                                                                <a href="%s" style="
                                                                  display: inline-block;
                                                                  background-color: #3F3368;
                                                                  color: #ffffff;
                                                                  text-decoration: none;
                                                                  padding: 14px 22px;
                                                                  border-radius: 16px;
                                                                  font-size: 16px;
                                                                  font-weight: bold;
                                                                ">Activate Account</a>
                                <p style="text-align: center; font-size: 14px; color: #666; font-style: italic;"><strong>Note:</strong> This activation link will expire in 24 hours for security reasons.</p>
                             </div>
             
                            <p style="font-size: 16px;">If you didn't expect this invitation or believe it was sent by error, please ignore this email or contact our support team.</p>
             
                           <p style="font-size: 16px;">Best regards,<br>The UrBreath Team</p>
                          </div>
                        </body>
                        </html>
             """ ;

  private static final String RESET_PASSWORD_EMAIL_TEMPLATE = """
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <titleReset Password</title>
            </head>
            <body style="font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; line-height: 1.5;">
              <div style="max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);">
                <p style="font-size: 16px;">Hello %s,</p>
            
                <p style="font-size: 16px;">You requested to reset password in UrBreath. Click the button below to set up a new password.</p>
            
                 <div style="text-align: center; margin: 40px 0;">
                                                    <a href="%s" style="
                                                      display: inline-block;
                                                      background-color: #3F3368;
                                                      color: #ffffff;
                                                      text-decoration: none;
                                                      padding: 14px 22px;
                                                      border-radius: 16px;
                                                      font-size: 16px;
                                                      font-weight: bold;
                                                    ">Reset Password</a>
                 </div>
            
                <p style="font-size: 16px;">If you didn't expect this email or believe it was sent by error, please ignore this email or contact our support team.</p>
            
                <p style="font-size: 16px;">Best regards,<br>The UrBreath Team</p>
              </div>
            </body>
            </html>
            """;


  public EmailService(JavaMailSender javaMailSender) {
    this.javaMailSender = javaMailSender;
  }

  /**
   *  Method to send an email based on the text, subject, username and subject provided as parameters
   *
   * @param recipientAddress : To email address
   * @param text : Text to include
   * @param subject : Subject of the email
   * @param fromUsername : From email address
   */
  @Override
  public void sendMessage(String recipientAddress, String text, String subject, String fromUsername) {
    try {
      MimeMessage message = javaMailSender.createMimeMessage();
      MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
      helper.setFrom(mailUsername);
      helper.setTo(recipientAddress);
      helper.setSubject(subject);
      helper.setText(text, true);
      log.info("Sending message to email: {}", recipientAddress);
      javaMailSender.send(message);
    } catch (MessagingException e) {
      log.error("Unable to send message to email: {} - Error: {}", recipientAddress, e.getMessage());
    }
  }

  /**
   * Creates a unique activation link with random generated token and a default expiration time and set it as attribute to the user
   */
  @Override
  @Async("asyncPoolTaskExecutor")
  public void sendActivationLink(String username, String email, String activationToken) {
      CompletableFuture.runAsync(() -> {
          // Create the activation link
          String activationLink = String.format("%s/activate-account?token=%s", frontendUrl, activationToken);

          // Create the email template
          String htmlContent = String.format(ACTIVATE_ACCOUNT_EMAIL_TEMPLATE, username, activationLink
          );

          // Call function to send email
          sendMessage(email, htmlContent, SUBJECT_ACTIVATE_STRING, mailUsername);
      });
  }
  
  /**
   * Email reset user's password
   */
  @Override
  @Async("asyncPoolTaskExecutor")
  public void sendResetPasswordLink(String username, String email, String resetToken) {
      CompletableFuture.runAsync(() -> {
          // Create the activation link
          String resetPasswordLink = String.format("%s/reset-password?token=%s", frontendUrl, resetToken);

          // Create the email template
          String htmlContent = String.format(RESET_PASSWORD_EMAIL_TEMPLATE, username, resetPasswordLink
          );

          // Call function to send email
          sendMessage(email, htmlContent, SUBJECT_RESET_STRING, mailUsername);
      });
  }
}

