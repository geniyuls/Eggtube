package com.jykim.eggtube.results.user;

import com.jykim.eggtube.results.Result;

public enum RegisterResult implements Result {
    FAILURE_DUPLICATE_CONTACT,
    FAILURE_DUPLICATE_EMAIL,
    FAILURE_DUPLICATE_NICKNAME,
}
