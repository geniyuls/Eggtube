package com.jykim.eggtube.mappers;

import com.jykim.eggtube.entities.EmailTokenEntity;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface EmailTokenMapper {
    EmailTokenEntity selectEmailTokenByUserEmailAndKey(@Param("userEmail") String userEmail, @Param("key") String key);
    int updateEmailToken(EmailTokenEntity emailToken);
int insertEmailToken(EmailTokenEntity emailTokenEntity);
}
