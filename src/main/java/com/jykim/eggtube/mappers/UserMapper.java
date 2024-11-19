package com.jykim.eggtube.mappers;

import com.jykim.eggtube.entities.UserEntity;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserMapper {
    int insertUser(UserEntity user);
    UserEntity selectUserByEmail(@Param("email") String email);

    UserEntity selectUserByContact(@Param("contact") String email);

    UserEntity selectUserByNickname(@Param("nickname") String email);
    int updateUser(UserEntity user);
}
