package com.example.loginDemo.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Entity
@Table(name = "orders")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class Order {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "order_id", updatable = false)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true) // OrderItem과 1:N 단방향
    @JoinColumn(name = "order_id") // FK 설정
    private List<OrderItem> orderItems;

    @Column(name = "order_date", nullable = false)
    private LocalDate orderDate;
}