package com.ic.oauth2.dto;

import lombok.Data;

@Data
public class TokenDTO {
   private String accessToken;
   private String refreshToken;    
}

