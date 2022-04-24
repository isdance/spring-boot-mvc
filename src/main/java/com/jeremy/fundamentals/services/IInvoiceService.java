package com.jeremy.fundamentals.services;

import com.jeremy.fundamentals.entities.Invoice;

import java.util.Optional;

public interface IInvoiceService {
    Optional<Invoice> findById(String id);
    Iterable<Invoice> findAllById(String id);

//    Iterable<Invoice> findAllById(Iterable<String> ids);
}
