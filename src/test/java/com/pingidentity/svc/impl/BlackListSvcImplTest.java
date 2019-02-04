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
package com.pingidentity.svc.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.pingidentity.svc.impl.BlackListSvcImpl;

import lombok.extern.slf4j.Slf4j;

/**
 * Test our blacklist implementation.
 */
@Slf4j
public class BlackListSvcImplTest {

    private BlackListSvcImpl bl;
    private String ip1 = "1.1.1.1";
    private String ip2 = "2.2.2.2";
    private String ip3 = "3.3.3.3";

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    @Before
    public void setUp() {
        log.debug("In before...");
        bl = new BlackListSvcImpl();
    }

    // Some helper methods:
    
    /**
     * Assert the ip count and whether it's currently black listed.
     */
    void assertIp(String ip, long count, boolean isBlacklisted) {
        assertEquals(count, bl.get(ip));
        assertEquals(isBlacklisted, bl.isBlackListed(ip));
    }

    /**
     * Asserts that two ordered maps are exactly the same; ie,
     * that the two maps' entries are in the same order.
     */
    void assertOrderedMaps(Map<String, Integer> expected, Map<String, Integer> actual) {
        String msg = "expected: " + expected + ", actual: " + actual;
        assertEquals(msg, expected.size(), actual.size());
        Iterator<String> eIt = expected.keySet().iterator();
        Iterator<String> aIt = actual.keySet().iterator();
        while (eIt.hasNext()) {
            String eKey = eIt.next();
            String aKey = aIt.next();
            assertEquals(msg, eKey, aKey);
            assertEquals(msg, expected.get(eKey), actual.get(aKey));
        }
    }
    
    /**
     * Create ordered Map from params.
     * ipAndCounts = pair of ipAddress and count (as Strings)
     * returns LinkedHashMap which preserves the order the input parameters
     */
    LinkedHashMap<String, Integer> getTopMap(String... ipAndCounts) {
        LinkedHashMap<String, Integer> result = new LinkedHashMap<>();
        for (int i = 0; i < ipAndCounts.length; i++) {
            String ip = ipAndCounts[i];
            int count = Integer.parseInt(ipAndCounts[++i]);
            result.put(ip, count);
        }
        return result;
    }
    
    /**
     * Helper method to move forward the clock used by the blacklist.
     */
    void fastForward(long seconds) {
        bl.setClock(Clock.offset(bl.getClock(), Duration.ofSeconds(seconds)));
    }
    
    // Begin tests:
    
    /**
     * Test default state of the blacklist.
     */
    @Test
    public void testNewEmptyBlackList() {
        assertEquals(0L, bl.get(ip1));
        assertFalse(bl.isBlackListed(ip1));
        assertTrue(bl.getTopN(1).isEmpty());
    }

    /**
     * Test state of blacklist after a few tracking requests.
     */
    @Test
    public void testSimpleTrack() {
        // adding some data
        assertFalse(bl.track(ip1));
        assertFalse(bl.track(ip1));
        assertFalse(bl.track(ip1));
        assertFalse(bl.track(ip2));

        assertIp(ip1, 3L, false); // all requests are accounted for, not blacklisted
        assertIp(ip2, 1L, false);
        assertOrderedMaps(getTopMap(ip1, "0", ip2, "0"), bl.getTopN(2));
    }

    /**
     * Test state after blacklisting.
     */
    @Test
    public void testTrackWithMaxBlackList() {
        bl.setMax(2); // anything > 1 will be blacklisted

        // adding some data
        assertFalse(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertFalse(bl.track(ip2));
        assertFalse(bl.track(ip3));
        assertTrue(bl.track(ip3));

        assertIp(ip1, 2L, true); // we don't count blacklist violations as in request counts
        assertIp(ip2, 1L, false);
        assertIp(ip3, 2L, true);
        // checking blacklist violations
        assertOrderedMaps(getTopMap(ip1, "2", ip3, "1", ip2, "0"), bl.getTopN(3));
    }

    /**
     * Checking that data is modified appropriately after the rolling window has passed.
     */
    @Test
    public void testTrackWithRollingWindow() {
        bl.setMax(2); // anything > 1 will be blacklisted
        bl.setWindow(1L); // rolling window is only 1 sec

        // adding some data
        assertFalse(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertFalse(bl.track(ip2));
        assertFalse(bl.track(ip3));
        assertTrue(bl.track(ip3));

        fastForward(1L); // fast-forward past rolling window

        assertIp(ip1, 0L, true); // still blacklisted as duration is 5 min
        assertIp(ip2, 0L, false);
        assertIp(ip3, 0L, true);
        assertOrderedMaps(getTopMap(ip1, "0", ip2, "0", ip3, "0"), bl.getTopN(3)); // topN window has 'rolled'

        // adding some more data
        assertTrue(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertFalse(bl.track(ip2));
        assertTrue(bl.track(ip3));
        assertTrue(bl.track(ip3));

        assertIp(ip1, 0L, true);
        assertIp(ip2, 1L, false);
        assertIp(ip3, 0L, true);
        assertOrderedMaps(getTopMap(ip1, "3", ip3, "2", ip2, "0"), bl.getTopN(3));
    }

    @Test
    public void testTrackWithBlacklistDuration() {
        bl.setMax(2); // anything > 1 will be blacklisted
        bl.setDuration(1L); // blacklist duration is only 1 sec

        // adding some data
        assertFalse(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertFalse(bl.track(ip2));
        assertFalse(bl.track(ip3));
        assertTrue(bl.track(ip3));

        fastForward(1L); // fast-forward past blacklist duration

        assertIp(ip1, 2L, false); // counts still show up as window is default value (5m)
        assertIp(ip2, 1L, false);
        assertIp(ip3, 2L, false);
        // violations still show up as window is default value
        assertOrderedMaps(getTopMap(ip1, "2", ip3, "1", ip2, "0"), bl.getTopN(3));

        // adding some more data
        assertTrue(bl.track(ip1)); // all new requests from existing ips are blacklisted
        assertTrue(bl.track(ip3));

        assertIp(ip1, 3L, true);
        assertIp(ip2, 1L, false);
        assertIp(ip3, 3L, true);
        assertOrderedMaps(getTopMap(ip1, "3", ip3, "2", ip2, "0"), bl.getTopN(3));
    }
    
    /**
     * Additional topN() tests that weren't tested during other test cases.
     */
    @Test
    public void testTopN() {
        bl.setMax(2); // anything > 1 will be blacklisted

        // adding some data
        assertFalse(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertFalse(bl.track(ip2));
        assertFalse(bl.track(ip3));
        assertTrue(bl.track(ip3));

        // request for more entries than we have
        assertOrderedMaps(getTopMap(ip1, "2", ip3, "1", ip2, "0"), bl.getTopN(4));
        assertOrderedMaps(getTopMap(ip1, "2", ip3, "1", ip2, "0"), bl.getTopN(3));
        // check where getTopN < # of blacklisted ips
        assertOrderedMaps(getTopMap(ip1, "2", ip3, "1"), bl.getTopN(2));
        assertOrderedMaps(getTopMap(ip1, "2"), bl.getTopN(1));
        assertOrderedMaps(Collections.emptyMap(), bl.getTopN(0));
        
        // assert that exception is thrown for negative numbers
        thrown.expect(IllegalArgumentException.class);
        assertOrderedMaps(Collections.emptyMap(), bl.getTopN(-1));
    }
    
    /**
     * Testing the cleanup thread.
     */
    @Test
    public void testCleanupThread() throws InterruptedException {
        // threshold = 2, window = duration = cleanupInterval = 1 sec
        bl = new BlackListSvcImpl(new ConcurrentHashMap<>(), Clock.systemDefaultZone(), 
            1L, 1L, 2, 1L, Executors.newSingleThreadExecutor()); 
        bl.startCleanupThread(); // have to manually call method as we've used the non default constructor
        
        // adding some data
        assertFalse(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertTrue(bl.track(ip1));
        assertFalse(bl.track(ip2));
        assertFalse(bl.track(ip3));
        assertTrue(bl.track(ip3));
        
        // manually run clean up and ensure that nothing is removed, because all tracked ips have counts
        bl.cleanup();
        assertIp(ip1, 2L, true);
        assertIp(ip2, 1L, false);
        assertIp(ip3, 2L, true);
        assertOrderedMaps(getTopMap(ip1, "2", ip3, "1", ip2, "0"), bl.getTopN(3));

        // sleep here to allow thread to try to clean everything up, as counts and violations have expired
        Thread.sleep(1100L); 

        assertIp(ip1, 0L, false); // no more counts
        assertIp(ip2, 0L, false);
        assertIp(ip3, 0L, false);
        assertOrderedMaps(Collections.emptyMap(), bl.getTopN(3)); // no more violations
        // db entries have also been removed
        assertEquals(0, bl.getDb().size());
    }
}
