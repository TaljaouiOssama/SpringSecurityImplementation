package com.ossama.springsecurityimplementation.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RoleUserDto {
    private String role;
    private  String user;

}
