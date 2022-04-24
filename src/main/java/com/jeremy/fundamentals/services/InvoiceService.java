package com.jeremy.fundamentals.services;

import com.jeremy.fundamentals.entities.Customer;
import com.jeremy.fundamentals.entities.Invoice;
import com.jeremy.fundamentals.repositories.InvoiceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.*;
import java.util.Optional;

@Service
public class InvoiceService implements IInvoiceService{
    @PersistenceContext
    EntityManager em;

    @Autowired
    private InvoiceRepository invoiceRepository;

    @Override
    public Optional<Invoice> findById(String id) {

        return invoiceRepository.findById(id);
    }

    public Iterable<Invoice> findAllById(String stockCode) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Invoice> cq = cb.createQuery(Invoice.class);
        Root<Invoice> invoiceRoot = cq.from(Invoice.class);
        invoiceRoot.fetch("Customer");

        Predicate stockCodePredicate = cb.equal(invoiceRoot.get("StockCode"), stockCode);
        cq.where(stockCodePredicate);

//        Join<Invoice, Customer> bJoin= invoiceRoot.join("customer", JoinType.LEFT);
//        bJoin.on(stockCodePredicate);

        TypedQuery<Invoice> query = em.createQuery(cq);
//        TypedQuery<Invoice> query = em.createQuery("Select i from Invoice i join fetch i.Customer where i.StockCode = :stockcode", Invoice.class)
//                .setParameter("stockcode", stockCode);
        return query.getResultList();
//        return invoiceRepository.findAllById(ids);
    }
}
