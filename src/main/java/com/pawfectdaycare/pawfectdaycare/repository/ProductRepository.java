package com.pawfectdaycare.pawfectdaycare.repository;
import com.pawfectdaycare.pawfectdaycare.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {
}
