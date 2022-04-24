package com.jeremy.fundamentals.entities;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "invoices")
@Getter
@Setter
public class Invoice implements Serializable {
    @Id
    @Column(name="stockcode", nullable = false)
    private String StockCode;

    @Column(name="quantity", nullable = false)
    private int Quantity;

    @Column(name="invoicedate", nullable = false)
    private Date InvoiceDate;

    @Column(name="unitprice", nullable = false)
    private Double UnitPrice;

    // must hide this if you defind a navigation property with JoinColumn
    // org.hibernate.MappingException: Repeated column in mapping for entity: com.jeremy.fundamentals.entities.Invoice column: customerid
//    @Column(name="customerid", nullable = false)
//    public Integer CustomerId;

    @Column(name="country", nullable = false)
    private String Country;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "customerid")
    private Customer Customer;
}
