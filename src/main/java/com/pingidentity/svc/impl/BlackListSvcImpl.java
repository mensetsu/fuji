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

import java.time.Clock;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.pingidentity.svc.BlackListSvc;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

/**
 * Implements blacklist service in memory with rolling time window as defined the the README.
 * 
 * Please consult the README file for IDE (with lombok) setup instructions as well as
 * discussion points regarding design decisions, etc.  
 */
@Slf4j
@AllArgsConstructor
public class BlackListSvcImpl implements BlackListSvc {

    // default constants
    final static long ROLLING_TIME_WINDOW_SEC = TimeUnit.MINUTES.toSeconds(5);
    final static long BLACKLIST_DURATION_SEC = TimeUnit.MINUTES.toSeconds(5);
    final static int BAD_REQUEST_THRESHOLD = 20;
    final static int CLEANUP_INTERVAL_SECONDS = 60;

    // Most of the Getter/Setter methods are package-level for testing purposes
    @Getter(AccessLevel.PACKAGE)
    private ConcurrentMap<String, Tracking> db;
    @Getter @Setter
    private Clock clock;
    @Setter(AccessLevel.PACKAGE)
    private long duration;
    @Setter(AccessLevel.PACKAGE)
    private long window;
    @Setter(AccessLevel.PACKAGE)
    private int max;
    @Getter @Setter(AccessLevel.PACKAGE)
    private long cleanupInterval;
    private ExecutorService executor;
    
    /**
     * Default constructor: all consumers must use this constructor to ensure that the
     * variables are set to default values and the cleanup thread is started.
     * 
     * The AllArgsConstructor is only provided for testing purposes.
     */
    public BlackListSvcImpl() {
        this(new ConcurrentHashMap<>(), Clock.systemDefaultZone(), 
            BLACKLIST_DURATION_SEC, ROLLING_TIME_WINDOW_SEC, BAD_REQUEST_THRESHOLD,
            CLEANUP_INTERVAL_SECONDS, Executors.newSingleThreadExecutor());
        // try to keep memory usage reasonable
        startCleanupThread();
    }
    
    /**
     * Gets current epoch seconds.
     */
    private long now() {
        return clock.instant().getEpochSecond();
    }

    /**
     * Track the ip address handling the following cases:
     * 1.) ip entry doesn't exit
     * 2.) ip is currently blacklisted (existing)
     * 3.) ip is blacklisted due to this request (new)
     * 4.) ip is not yet blacklisted
     */
    @Override
    public boolean track(String ip) {
        long now = now();
        
        // 1.) add new entry
        Tracking old = db.putIfAbsent(ip, new Tracking(now));
        if (old == null) { // it was empty as we don't allow null previous values
            return false;
        }
        // 2.) update existing blacklist end time
        Tracking tracking = db.get(ip);
        if (isBlackListed(ip)) { // update bl duration
            tracking.updateBlackList(now + duration, now);
            return true;
        }
        // add request to db
        // 3.) add to blacklist if request count is over the max
        tracking.track(now);
        if (get(ip) >= max) { // initiate bl; note: get() will also clean out old requests
            tracking.updateBlackList(now + duration, now);
            return true;
        }
        // otherwise 4.) do nothing, we are still under the limit (unblacklisted)
        return false;
    }

    /**
     * The ip is blacklisted if there is a tracking entry in the db and we have moved past the
     * blacklist end time.
     */
    @Override
    public boolean isBlackListed(String ip) {
        if (!db.containsKey(ip)) {
            return false;
        }
        return db.get(ip).isBlackListed(now());
    }

    /**
     * Get the current request count accumulated during the rolling window.  
     * This is done by first removing older requests, then returning a count of remaining requests.
     */
    @Override
    public long get(String ip) {
        if (!db.containsKey(ip)) {
            return 0L;
        }
        // removing entries outside of rolling window
        return db.get(ip).count(now() - window);
    }

    /**
     * Returns a map of the top N ips with the most blacklist violations (in descending order).
     */
    @Override
    public Map<String, Integer> getTopN(int n) {
        long from = now() - window;
//        return db.entrySet().stream()
//            .map(e -> new AbstractMap.SimpleEntry<>(e.getKey(), 
//                e.getValue().blackListCount(from))) // map to <ip, blackListCount>
//            .sorted(reverseOrder(Map.Entry.comparingByValue())).limit(n) // sort by blCount (descending), limit to n
//            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, 
//                (old, neuw) -> old, LinkedHashMap::new)); // return result as ordered map
        if (n < 0) {
            throw new IllegalArgumentException("Stream throws this automatically...");
        }
        Map<String, Integer> result = new LinkedHashMap<>();
        if (n == 0) {
            return result;
        }
        // else we have to go thru all the items
        PriorityQueue<Map.Entry<String, Integer>> pq = new PriorityQueue<>((a, b) -> { // sort 1st by value then keys
            int valueDiff = a.getValue() - b.getValue(); // reverse order; ie; queue will be lowest->highest
            if (valueDiff == 0) { // if same value reverse alphabetical order of keys
                return -a.getKey().compareTo(b.getKey());
            }
            return valueDiff;
        });
        for (Map.Entry<String, Tracking> e : db.entrySet()) {
            int blackListCount = e.getValue().blackListCount(from);
            Map.Entry<String, Integer> entry = new AbstractMap.SimpleEntry<String, Integer>(e.getKey(), blackListCount);
            pq.add(entry);
            if (pq.size() > n) {
                pq.poll(); // remove lowest element
            }
        };
        for (int i = 0; i < n; i++) {
            Map.Entry<String, Integer> e = pq.poll();
            if (e == null) { // just in case n > size()
                break;
            }
            result.put(e.getKey(), e.getValue());
        }
        ArrayList<String> keys = new ArrayList<>(result.keySet());
        Collections.reverse(keys);
        return keys.stream().collect(Collectors.toMap(e -> e, e -> result.get(e), 
            (old, neuw) -> old, LinkedHashMap::new));
    }
    
    /**
     * Starts a clean up thread that will call cleanup() to manage the size of the db; ie,
     * remove old entiries from Tracking lists and remove ips from db if they are no longer used
     */
    void startCleanupThread() {
        executor.execute(() -> {
            while (true) {
                try {
                    TimeUnit.SECONDS.sleep(getCleanupInterval());
                } catch (InterruptedException e) {
                    log.error("Clean up thread was interrupted: {}", e);
                    break; // exit loop
                }
                // run clean up method
                cleanup();
            }
        });
    }
    
    /**
     * Method that does the actual clean up of the db, removes old requests and violations and
     * if the current request count is 0 
     * and the current blacklist violation count is 0, will remove the ip entry from db.
     */
    void cleanup() {
        log.info("Running cleanup.");
        db.keySet().stream().forEach(ip -> {
            long now = now();
            long from = now - window;
            db.merge(ip, new Tracking(now), (old, neuw) -> {
                if (old.count(from) == 0L && old.blackListCount(from) == 0L) {
                    log.info("Deleting entry as it's empty: {}.", ip);
                    return null;
                }
                return old; // just return the old tracking
            });
        });
    }
}
