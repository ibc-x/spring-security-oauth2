package com.ic.ioauth2.dto;

import lombok.Data;

@Data
public class TokenDTO {
   //private Long userId;
   private String accessToken;
   private String refreshToken;    
}

