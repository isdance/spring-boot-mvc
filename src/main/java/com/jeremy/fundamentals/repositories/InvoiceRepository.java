package com.jeremy.fundamentals.repositories;

import com.jeremy.fundamentals.entities.Invoice;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface InvoiceRepository extends CrudRepository<Invoice, String> {
}
