/***************************************************************************
 * Copyright (C) 2016 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * You may not copy or use this file, in either source code or executable
 * form, except in compliance with terms set by Ping Identity Corporation.
 * For further information please contact:
 *
 *     Ping Identity Corporation
 *     1001 17th Street Suite 100
 *     Denver, CO 80202
 *     303.468.2900
 *     http://www.pingidentity.com
 *
 **************************************************************************/
package com.pingidentity.svc;

import java.util.Map;


/**
 * See README
 */
public interface BlackListSvc
{
    /**
     * Assignment 1:
     * Puts the IP address into the tracking service, increment the counter mapped to the address and return the blacklist status.
     * @param ipAddress IP address, please only consider IPv4 format address such as 192.168.0.1
     * @return if the IP address is black listed at the moment
     */
    boolean track(String ipAddress);
    
    /**
     * Assignment 1:
     * Is the IP address black listed.
     * @param ipAddress IP address to check, please only consider IPv4 format address such as 192.168.0.1
     * @return true if the IP address is black listed at the moment
     */
    boolean isBlackListed(String ipAddress);
    
    /**
     * Assignment 1:
     * Gets the the counter mapped to the address.
     * @param ipAddress IP address, please only consider IPV4 format address such as 192.168.0.1
     * @return the current counter of the address
     */
    long get(String ipAddress);
    
    /**
     * Assignment 2:
     * Notice: this is bonus assignment.
     * 
     * Gets the top N IP addresses and the associated counter that are black listed ordered by their counters.
     * @param n the number of top UP addresses that are black listed
     * @return the top N IP addresses and counters ordered by their counter in descending order
     */
    Map<String, Integer> getTopN(int n);

}
