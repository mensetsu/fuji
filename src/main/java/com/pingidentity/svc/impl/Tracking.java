/***************************************************************************
 * Copyright (C) 2015 Ping Identity Corporation
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
package com.pingidentity.svc.impl;

import java.util.ArrayList;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * State object for an associated ip.
 * Holds requests and blacklist violations as well as the latest blacklist end time.
 * Write operations are locked using the two lists so lists are thread-safe.
 */
@Slf4j
@AllArgsConstructor
public class Tracking {
    
    private long blacklistEnd; // end time
    private List<Long> blacklistRequestTimes;
    private List<Long> requestTimes;

    /**
     * Creates a new Tracking object with a single request.
     * Please use this constructor as it initializes all the fields properly.
     */
    public Tracking(long now) {
        // blacklist end time will always be < now, so isBlackListed() will be false initially
        this(0L, new ArrayList<>(), new ArrayList<>());
        track(now); // add to requestTimes
        log.trace("New tracking created for: {}", now);
    }
    
    /**
     * Check if we've past the blacklist end time.
     */
    public boolean isBlackListed(long now) {
        return now < blacklistEnd;
    }
    
    /**
     * Track current request.
     * We lock on the request list as it's will modify the list.
     */
    public void track(long now) {
        synchronized(requestTimes) {
            requestTimes.add(now);
        }
    }
    
    /**
     * Get current count of requests within rolling window from time.
     * We lock on the request list as we may modify it.
     */
    public long count(long from) {
        synchronized(requestTimes) {
            requestTimes.removeIf(e -> e <= from);
            return requestTimes.size();
        }
    }
    
    /**
     * Update an existing black listed entry, keep track of violation, update end time.
     * We lock on black list violations list as we are modifying it.
     */
    public void updateBlackList(long newEndTime, long now) {
        synchronized(blacklistRequestTimes) {
            blacklistEnd = newEndTime;
            blacklistRequestTimes.add(now);
        }
    }
    
    /**
     * Returns the number of black list violations after any removals of times before from parameter.
     * We lock on black list violations list as we may modify it.
     */
    public int blackListCount(long from) {
        synchronized(blacklistRequestTimes) {
            blacklistRequestTimes.removeIf(e -> e <= from);
            return blacklistRequestTimes.size();
        }
    }
}
