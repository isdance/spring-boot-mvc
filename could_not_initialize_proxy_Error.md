[Source](https://knpcode.com/spring/lazyinitializationexception-could-not-initialize-proxy-no-session/)

#### 1. Why LazyInitializationException : could not initialize proxy

You may encounter this error while having JPA mappings and trying to access associated object (child object) from the parent object. As you must be knowing that as an optimization associations are fetched lazily. In fact in JPA by default OneToMany and ManyToMany are LAZY and associated objects are loaded into session only when explicitly accessed in code. That should give you the first clue why LazyInitializationException is thrown.

Taking this explanation further to how these associated objects are actually loaded. Hibernate creates a proxy object for the child object and populate the parent object with this proxy. This proxy has a reference back to the Hibernate session. Whenever a method is called on the proxy object, it checks to see if the proxy has been initialized or not. If not initialized then it uses the Hibernate session to create a new query to the database and populates the object. That pertains to the other part of the error where it says “could not initialize proxy – no Session”.

With this explanation it should be clear to you that this error is coming up because you are `trying to access an object that has to be lazily loaded`. When you actually try to access that object by that time session is closed so the proxy object can not to be initialized to get the real object.

What happen is, Hibernate creates a proxy Account object and try to get the real object only when it is accessed in the code. In the code it is this line where actual object has to be fetched.
`for(Customer customer : i.getCustomer()) `
But the problem is session is already closed in the DAO layer and there is no way to initialize the proxy object now.

### 2. Fixing could not initialize proxy – no session error

You may be thinking of keeping the session open for a longer time (opening and closing it in view layer rather than in Service) or to have fetch mode as ‘Eager’ while configuring @OneToMany mapping.

Of course, keeping the session for a longer duration is not a good solution and it will create more problems in terms of transaction handling and slowing down the application.

Using FetchType.EAGER will fix the error but then you are always fetching the associations even when you are not using them. Also the number of additional queries that are executed grows.

`Using JOIN FETCH clause`
Best way to fix this error is to use JOIN FETCH clause which not only joins the entities but also fetches the associated entities.

```java
public Iterable<Invoice> findAllById(String stockCode) {
    TypedQuery<Invoice> query = em.createQuery("Select i from Invoice i join fetch i.Customer where i.StockCode = :stockcode", Invoice.class)
            .setParameter("stockcode", stockCode);
    return query.getResultList();
}
```

If you are using Criteria then the same method can be written as given below-

```java
public Iterable<Invoice> findAllById(String stockCode) {
    CriteriaBuilder cb = em.getCriteriaBuilder();
    CriteriaQuery<Invoice> cq = cb.createQuery(Invoice.class);
    Root<Invoice> invoiceRoot = cq.from(Invoice.class);
    invoiceRoot.fetch("Customer");

    Predicate stockCodePredicate = cb.equal(invoiceRoot.get("StockCode"), stockCode);
    cq.where(stockCodePredicate);

    TypedQuery<Invoice> query = em.createQuery(cq);
    return query.getResultList();
}
```

Note:

1. The standard 'join' doesn't work with LAZY.

Below join does NOT work. Will throw same error as before. `Caused by: org.hibernate.LazyInitializationException: could not initialize proxy [com.jeremy.fundamentals.entities.Customer#14735] - no Session`

```java
 public Iterable<Invoice> findAllById(String stockCode) {
    CriteriaBuilder cb = em.getCriteriaBuilder();
    CriteriaQuery<Invoice> cq = cb.createQuery(Invoice.class);
    Root<Invoice> invoiceRoot = cq.from(Invoice.class);

    Predicate stockCodePredicate = cb.equal(invoiceRoot.get("StockCode"), stockCode);

    Join<Invoice, Customer> bJoin= invoiceRoot.join("Customer", JoinType.LEFT);
    bJoin.on(stockCodePredicate);

    TypedQuery<Invoice> query = em.createQuery(cq);
    return query.getResultList();
}
```
