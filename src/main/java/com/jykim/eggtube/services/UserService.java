package com.jykim.eggtube.services;

import com.jykim.eggtube.entities.EmailTokenEntity;
import com.jykim.eggtube.entities.UserEntity;
import com.jykim.eggtube.exceptions.TransactionalException;
import com.jykim.eggtube.mappers.EmailTokenMapper;
import com.jykim.eggtube.mappers.UserMapper;
import com.jykim.eggtube.results.CommonResult;
import com.jykim.eggtube.results.Result;
import com.jykim.eggtube.results.user.LoginResult;
import com.jykim.eggtube.results.user.RegisterResult;
import com.jykim.eggtube.results.user.ResolveRecoverPasswordResult;
import com.jykim.eggtube.results.user.ValidateEmailResult;
import com.jykim.eggtube.utils.CryptoUtils;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.time.LocalDateTime;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserMapper userMapper;
    private final EmailTokenMapper emailTokenMapper;
    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    public Result login(UserEntity user) {
        if (user == null ||
                user.getEmail() == null || user.getEmail().length() < 8 || user.getEmail().length() > 50 ||
                user.getPassword() == null || user.getPassword().length() < 6 || user.getPassword().length() > 50) {
            return CommonResult.FAILURE;
        }
        UserEntity dbUser = this.userMapper.selectUserByEmail(user.getEmail());
        if (dbUser == null || dbUser.getDeletedAt() != null) {
            return CommonResult.FAILURE;
        }
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        if (!encoder.matches(user.getPassword(), dbUser.getPassword())) {
            return CommonResult.FAILURE;
        }
        if(!dbUser.isVerified()){
            return LoginResult.FAILURE_NOT_VERIFIED;
        }
        if (dbUser.isSuspended()){
            return LoginResult.FAILURE_SUSPENDED;
        }
        user.setPassword(dbUser.getPassword());
        user.setNickname(dbUser.getNickname());
        user.setContact(dbUser.getContact());
        user.setCreatedAt(dbUser.getCreatedAt());
        user.setDeletedAt(dbUser.getDeletedAt());
        user.setAdmin(dbUser.isAdmin());
        user.setSuspended(dbUser.isSuspended());
        user.setVerified(dbUser.isVerified());
        return CommonResult.SUCCESS;
    }

    public Result recoverEmail(UserEntity user){
        if (user == null || user.getContact() == null || user.getContact().length() < 10 || user.getContact().length() > 12) {
            return CommonResult.FAILURE;
        }
        UserEntity dbUser = this.userMapper.selectUserByContact(user.getContact());
        if (dbUser ==null || dbUser.getDeletedAt() != null){
            return CommonResult.FAILURE;
        }
        user.setEmail(dbUser.getEmail());
        return CommonResult.SUCCESS;
    }

    @Transactional
    public Result provokeRecoverPassword(HttpServletRequest request, String email) throws MessagingException {
        if (email ==null || email.length() < 8 || email.length() >50) {
            return CommonResult.FAILURE;
        }
        UserEntity user = this.userMapper.selectUserByEmail(email);
        if(user == null || user.getDeletedAt() != null){
            return CommonResult.FAILURE;
        }

        EmailTokenEntity emailToken = new EmailTokenEntity();
        emailToken.setUserEmail(user.getEmail());
        emailToken.setKey(CryptoUtils.hashSha512(String.format("%s%s%f%f", user.getEmail(), user.getPassword(), Math.random(), Math.random())));

        emailToken.setCreatedAt(LocalDateTime.now());
        emailToken.setExpiresAt(LocalDateTime.now().plusHours(24));
        emailToken.setUsed(false);
        if (this.emailTokenMapper.insertEmailToken(emailToken) == 0) {
            throw new TransactionalException();
        }
        String validationLink = String.format("%s://%s:%d/user/recover-password?userEmail=%s&key=%s", request.getScheme(), request.getServerName(), request.getServerPort(), emailToken.getUserEmail(), emailToken.getKey());
        Context context = new Context();
        context.setVariable("validationLink", validationLink);
        //thymleaf
        String mailText = this.templateEngine.process("email/recoverPassword", context);
        MimeMessage mimeMessage = this.mailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage);
        mimeMessageHelper.setFrom("yulisis123@gmail.com");
        mimeMessageHelper.setTo(emailToken.getUserEmail());
        mimeMessageHelper.setSubject("[애그튜브] 비밀번호 재설정 인증 링크");
        mimeMessageHelper.setText(mailText, true);
        this.mailSender.send(mimeMessage);
        return CommonResult.SUCCESS;
    }

    @Transactional
    // 오류떠야 발동함. 오류가 뜨면 하던거 다 취소하고 원복 **return으로 할 경우 오류가 아님
//    public Result register(UserEntity user) {
    public Result register(HttpServletRequest request, UserEntity user) throws MessagingException {
        if (user == null ||
                user.getEmail() == null || user.getEmail().length() < 8 || user.getEmail().length() > 50 ||
                user.getPassword() == null || user.getPassword().length() < 6 || user.getPassword().length() > 50 || user.getNickname() == null || user.getNickname().length() < 2 || user.getNickname().length() > 10 ||
                user.getContact() == null || user.getContact().length() < 10 || user.getContact().length() > 12) {
            return CommonResult.FAILURE;
        }
        if (this.userMapper.selectUserByEmail(user.getEmail()) != null) {
            return RegisterResult.FAILURE_DUPLICATE_EMAIL;
        }
        if (this.userMapper.selectUserByNickname(user.getNickname()) != null) {
            return RegisterResult.FAILURE_DUPLICATE_NICKNAME;
        }
        if (this.userMapper.selectUserByContact(user.getContact()) != null) {
            return RegisterResult.FAILURE_DUPLICATE_CONTACT;
        }

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        user.setPassword(encoder.encode(user.getPassword()));

        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        user.setDeletedAt(null);
        user.setAdmin(false);
        user.setSuspended(false);
        user.setVerified(false);
        if (this.userMapper.insertUser(user) == 0) {
            throw new TransactionalException();
        }
        EmailTokenEntity emailToken = new EmailTokenEntity();
        emailToken.setUserEmail(user.getEmail());
        emailToken.setKey(CryptoUtils.hashSha512(String.format("%s%s%f%f", user.getEmail(), user.getPassword(), Math.random(), Math.random())));

        emailToken.setCreatedAt(LocalDateTime.now());
        emailToken.setExpiresAt(LocalDateTime.now().plusHours(24));
        emailToken.setUsed(false);
        if (this.emailTokenMapper.insertEmailToken(emailToken) == 0) {
            throw new TransactionalException();
        }
        // TODO emailToken ISERT 하기
        // TODO @Transactional 걸고 설명하기
        // TODO 이메일 보내기

        String validationLink = String.format("%s://%s:%d/user/validate-email-token?userEmail=%s&key=%s", request.getScheme(), request.getServerName(), request.getServerPort(), emailToken.getUserEmail(), emailToken.getKey());
        Context context = new Context();
        context.setVariable("validationLink", validationLink);
        //thymleaf
        String mailText = this.templateEngine.process("email/register", context);
        MimeMessage mimeMessage = this.mailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage);
        mimeMessageHelper.setFrom("yulisis123@gmail.com");
        mimeMessageHelper.setTo(emailToken.getUserEmail());
        mimeMessageHelper.setSubject("[애그튜브] 회원가입 인증 링크");
        mimeMessageHelper.setText(mailText, true);
        this.mailSender.send(mimeMessage);
        return CommonResult.SUCCESS;
    }

    @Transactional
    public Result resolveRecoverPassword(EmailTokenEntity emailToken, String password) {
        if (emailToken == null || emailToken.getUserEmail() == null || emailToken.getUserEmail().length() < 8 || emailToken.getUserEmail().length() > 50 || emailToken.getKey() == null || emailToken.getKey().length() != 128 || password == null || password.length() < 6 || password.length() >= 50) {
            return CommonResult.FAILURE;
        }
        EmailTokenEntity dbEmailToken = this.emailTokenMapper.selectEmailTokenByUserEmailAndKey(emailToken.getUserEmail(), emailToken.getKey());
        if(dbEmailToken == null || dbEmailToken.isUsed()) {
            return CommonResult.FAILURE;
        }
        if (dbEmailToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            return ResolveRecoverPasswordResult.FAILURE_EXPIRED;
        }
        dbEmailToken.setUsed(true);
        if(this.emailTokenMapper.updateEmailToken(dbEmailToken) ==0){
            throw new TransactionalException();
        }
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        UserEntity user = this.userMapper.selectUserByEmail(emailToken.getUserEmail());
        user.setPassword(encoder.encode(password));
        if(this.userMapper.updateUser(user) == 0) {
            throw new TransactionalException();
        }
        return CommonResult.SUCCESS;
    }

    public Result validateEmailToken(EmailTokenEntity emailToken) {
        if (emailToken == null || emailToken.getUserEmail() == null || emailToken.getUserEmail().length() < 8 || emailToken.getUserEmail().length() > 50 || emailToken.getKey() == null || emailToken.getKey().length() != 128) {
            return CommonResult.FAILURE;
        }
        EmailTokenEntity dbEmailToken = this.emailTokenMapper.selectEmailTokenByUserEmailAndKey(emailToken.getUserEmail(), emailToken.getKey());
        if (dbEmailToken == null || dbEmailToken.isUsed()) {
            // DB에 존재하지 않거나, 이미 사용된 토큰이면
            return CommonResult.FAILURE;
        }
        if (dbEmailToken.getExpiresAt().isBefore((LocalDateTime.now()))) {
            // "이메[일 토큰의 만료 일시"가 "현재 일시"보다 과거(isBefore)면,
            return ValidateEmailResult.FAILURE_EXPIRED;
        }
        dbEmailToken.setUsed(true); // 토큰을 사용된 것으로 처리한다. (인증안 한번만 가능하므로)
        if (this.emailTokenMapper.updateEmailToken(dbEmailToken) == 0) {
            throw new TransactionalException();
        }
        UserEntity user = this.userMapper.selectUserByEmail(emailToken.getUserEmail());
        user.setVerified(true); //사용자에 대해 인증처리 된 것으로 수정한다.
        if (this.userMapper.updateUser(user) == 0) {
            throw new TransactionalException();
        }
        return CommonResult.SUCCESS;
    }

}
