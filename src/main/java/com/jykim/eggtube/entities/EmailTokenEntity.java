package com.jykim.eggtube.entities;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Setter
@Getter
@EqualsAndHashCode(of = {"userEmail", "key"})
public class EmailTokenEntity {
    private String userEmail;
    private String key;
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
    private boolean isUsed;
}
