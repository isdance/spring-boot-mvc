package com.jeremy.fundamentals.entities;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "customers")
@Getter
@Setter
public class Customer implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="id", nullable = false)
    private Integer Id;

    @Column(name = "name", nullable = false)
    private String Name;

    @Column(name = "username", nullable = false)
    private String Username;

    @Column(name = "password", nullable = false)
    private String Password;
}
