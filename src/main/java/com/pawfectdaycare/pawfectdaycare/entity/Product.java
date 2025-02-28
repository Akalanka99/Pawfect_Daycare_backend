package com.pawfectdaycare.pawfectdaycare.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity

@Table(name = "product")
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;

    private String category;



    private Integer price;

    public Product(Long id) {
        this.id = id;
    }

    @Column(length = 1024)
    private String description;
    public Product() {
    }
    public Product(Long id, String name, String category, Integer price, String description, String image) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.price = price;
        this.description = description;
        this.image = image;
    }

    private String image;
}
