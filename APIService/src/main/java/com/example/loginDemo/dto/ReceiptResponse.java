package com.example.loginDemo.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ReceiptResponse {
    private LocalDate purchaseDate; // 구매일자
    private List<String> matchedItems; // 매칭된 아이템들
}
